//! Limits how fast each client may make requests and guess passwords.
//!
//! - Every client IP (an IPv6 address counts as its /64) gets a token bucket
//!   of requests.
//! - Failed attempts (a wrong server password, or a wrong password for an
//!   account) count against the IP. An IP with a few recent failures is
//!   "bad"; with more it is banned, for longer each time it happens again.
//! - An account with several failed attempts (from anywhere) is throttled:
//!   an IP that hasn't logged into it recently must wait before each attempt
//!   at it (1 s, 5 s, 10 s, …), twice as long if the IP is bad, whose
//!   failures there also count double. The account itself is never locked:
//!   its owner gets in after a short wait, and right away from where they
//!   logged in before.
//!
//! Every table is bounded, so a flood of addresses or usernames can't use up
//! the server's memory; when one is full, entries that matter least are
//! dropped (never a banned IP or a throttled account for a newcomer).
//!
//! Handlers report what happened through extensions: `ServerPassRejected` on
//! the response, `AuthOutcome` on the request; the middleware (`middleware`)
//! does the bookkeeping.

use actix_web::{
    Error, HttpMessage, HttpResponse,
    body::{EitherBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    http::header,
    middleware::Next,
    web,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase", default)]
pub struct RateLimitConfig {
    /// Off only for local testing.
    pub enabled: bool,
    pub requests_per_second: f64,
    /// Requests an idle client may make at once (a page load, then syncing).
    pub request_burst: f64,
    /// Failures older than this are forgotten.
    pub failure_window_secs: u64,
    /// Failures (in the window) after which an IP counts as bad.
    pub bad_ip_failures: u32,
    /// Failures (in the window) after which an IP is banned.
    pub failures_to_ban: u32,
    /// The first ban's length; each further one (within a day of the last)
    /// is twice as long, up to `max_ban_secs`.
    pub ban_secs: u64,
    pub max_ban_secs: u64,
    /// Failures at an account (in the window, from anywhere) after which it
    /// is throttled, until a window passes without failures.
    pub account_failures_to_throttle: u32,
    /// How long an IP waits before each attempt at a throttled account: the
    /// first entry before its first attempt, and so on, then the last one.
    pub account_delays_secs: Vec<u64>,
    /// IPs that logged into an account aren't throttled for it for this long.
    pub trusted_ip_days: u64,
    pub max_tracked_ips: usize,
    pub max_tracked_accounts: usize,
    pub max_ips_per_account: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: 20.0,
            request_burst: 200.0,
            failure_window_secs: 15 * 60,
            bad_ip_failures: 3,
            failures_to_ban: 10,
            ban_secs: 15 * 60,
            max_ban_secs: 24 * 60 * 60,
            account_failures_to_throttle: 5,
            account_delays_secs: vec![1, 5, 10, 30, 60],
            trusted_ip_days: 30,
            max_tracked_ips: 100_000,
            max_tracked_accounts: 20_000,
            max_ips_per_account: 256,
        }
    }
}

/// A client: its IPv4 address, or its IPv6 /64 (which one user may hold
/// entirely).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ClientKey(u128);

impl ClientKey {
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self(u32::from(v4) as u128),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => Self(u32::from(v4) as u128),
                // the /64, marked so it can't equal an IPv4 address
                None => Self((u128::from(v6) & !((1u128 << 64) - 1)) | 1),
            },
        }
    }
}

/// The client's address: the peer's, or, when the peer is the local reverse
/// proxy, the one it reports in `X-Real-IP`. `None` when unknown (tests).
pub fn client_key(req: &ServiceRequest) -> Option<ClientKey> {
    let peer = req.peer_addr()?.ip();
    let ip = if peer.is_loopback() {
        req.headers()
            .get("X-Real-IP")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(peer)
    } else {
        peer
    };
    Some(ClientKey::from_ip(ip))
}

/// Set on a response that refused the server or policy password.
pub struct ServerPassRejected;

/// Set on a request by the account password check.
#[derive(Clone)]
pub enum AuthOutcome {
    Success {
        username: String,
    },
    /// `exists`: whether the account exists (only then is it tracked).
    Failure {
        username: String,
        exists: bool,
    },
}

#[derive(Debug, PartialEq)]
pub enum Verdict {
    Allow,
    Deny {
        retry_after: Duration,
        kind: DenyKind,
    },
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum DenyKind {
    /// Too many requests.
    RateLimited,
    /// Too many failed attempts from this IP.
    Banned,
    /// The account had many failed attempts; wait before trying it.
    Throttled,
}

struct IpState {
    tokens: f64,
    refilled: Instant,
    /// Recent failures (one entry per failure, two for one that counts
    /// double), oldest first; bounded.
    failures: VecDeque<Instant>,
    banned_until: Option<Instant>,
    offenses: u32,
    last_offense: Option<Instant>,
}

struct Attempts {
    count: u32,
    next_allowed: Instant,
}

#[derive(Default)]
struct AccountState {
    failures: VecDeque<Instant>,
    throttled_until: Option<Instant>,
    /// Attempts at the account (while throttled) by IP; bounded.
    attempts: HashMap<ClientKey, Attempts>,
    /// IPs that logged in, most recent last; bounded.
    trusted: Vec<(ClientKey, Instant)>,
}

const MAX_TRUSTED_PER_ACCOUNT: usize = 16;
const OFFENSE_MEMORY: Duration = Duration::from_secs(24 * 60 * 60);
const SWEEP_EVERY: Duration = Duration::from_secs(60);
/// How many entries to look at for one to drop when a table is full.
const EVICTION_SCAN: usize = 64;

struct State {
    ips: HashMap<ClientKey, IpState>,
    accounts: HashMap<String, AccountState>,
    last_sweep: Instant,
}

pub struct RateLimiter {
    config: RateLimitConfig,
    state: Mutex<State>,
}

/// Drops entries older than `window`, then the oldest beyond `cap`.
fn prune(events: &mut VecDeque<Instant>, now: Instant, window: Duration, cap: usize) {
    while events
        .front()
        .is_some_and(|t| now.saturating_duration_since(*t) >= window)
    {
        events.pop_front();
    }
    while events.len() > cap {
        events.pop_front();
    }
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            state: Mutex::new(State {
                ips: HashMap::new(),
                accounts: HashMap::new(),
                last_sweep: Instant::now(),
            }),
        }
    }

    fn window(&self) -> Duration {
        Duration::from_secs(self.config.failure_window_secs)
    }

    fn failure_cap(&self) -> usize {
        (self.config.failures_to_ban.max(self.config.bad_ip_failures) as usize).max(1) * 2
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // the state stays consistent even if a holder panicked
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The IP's entry, created if there's room (or room can be made).
    fn ip_entry<'a>(
        &self,
        state: &'a mut State,
        ip: ClientKey,
        now: Instant,
    ) -> Option<&'a mut IpState> {
        if !state.ips.contains_key(&ip) {
            if state.ips.len() >= self.config.max_tracked_ips {
                let victim = state
                    .ips
                    .iter()
                    .take(EVICTION_SCAN)
                    .find(|(_, s)| !s.banned_until.is_some_and(|t| t > now))
                    .map(|(k, _)| *k)?;
                state.ips.remove(&victim);
            }
            state.ips.insert(
                ip,
                IpState {
                    tokens: self.config.request_burst,
                    refilled: now,
                    failures: VecDeque::new(),
                    banned_until: None,
                    offenses: 0,
                    last_offense: None,
                },
            );
        }
        state.ips.get_mut(&ip)
    }

    fn is_bad(&self, state: &mut State, ip: ClientKey, now: Instant) -> bool {
        let window = self.window();
        let cap = self.failure_cap();
        let Some(s) = state.ips.get_mut(&ip) else {
            return false;
        };
        prune(&mut s.failures, now, window, cap);
        s.failures.len() >= self.config.bad_ip_failures as usize
            || s.last_offense
                .is_some_and(|t| now.saturating_duration_since(t) < OFFENSE_MEMORY)
    }

    /// Checks a request is allowed from `ip` (not banned, within its rate).
    pub fn check_request(&self, ip: ClientKey, now: Instant) -> Verdict {
        if !self.config.enabled {
            return Verdict::Allow;
        }
        let mut state = self.lock();
        self.sweep(&mut state, now);
        let (rate, burst) = (self.config.requests_per_second, self.config.request_burst);
        let Some(s) = self.ip_entry(&mut state, ip, now) else {
            // the table is full of banned IPs: let this one through
            return Verdict::Allow;
        };
        if let Some(until) = s.banned_until {
            if until > now {
                return Verdict::Deny {
                    retry_after: until - now,
                    kind: DenyKind::Banned,
                };
            }
            s.banned_until = None;
        }
        let elapsed = now.saturating_duration_since(s.refilled).as_secs_f64();
        s.tokens = (s.tokens + elapsed * rate).min(burst);
        s.refilled = now;
        if s.tokens < 1.0 {
            return Verdict::Deny {
                retry_after: Duration::from_secs_f64((1.0 - s.tokens) / rate),
                kind: DenyKind::RateLimited,
            };
        }
        s.tokens -= 1.0;
        Verdict::Allow
    }

    fn delay(&self, attempts: u32, bad: bool) -> Duration {
        let delays = &self.config.account_delays_secs;
        let secs = delays
            .get(attempts as usize)
            .or(delays.last())
            .copied()
            .unwrap_or(0);
        Duration::from_secs(if bad { secs * 2 } else { secs })
    }

    /// Checks `ip` may make an attempt at `username` now. Allowing one also
    /// starts the wait before the next (a successful login ends it).
    pub fn check_account(&self, username: &str, ip: ClientKey, now: Instant) -> Verdict {
        if !self.config.enabled {
            return Verdict::Allow;
        }
        let mut state = self.lock();
        let bad = self.is_bad(&mut state, ip, now);
        let trusted_for = Duration::from_secs(self.config.trusted_ip_days * 24 * 60 * 60);
        let max_ips = self.config.max_ips_per_account;
        let Some(account) = state.accounts.get_mut(username) else {
            return Verdict::Allow;
        };
        if !account.throttled_until.is_some_and(|t| t > now) {
            return Verdict::Allow;
        }
        if account
            .trusted
            .iter()
            .any(|(k, t)| *k == ip && now.saturating_duration_since(*t) < trusted_for)
        {
            return Verdict::Allow;
        }
        match account.attempts.get_mut(&ip) {
            None => {
                if account.attempts.len() >= max_ips {
                    // forget an IP whose wait is over, or else any
                    let victim = account
                        .attempts
                        .iter()
                        .take(EVICTION_SCAN)
                        .find(|(_, a)| a.next_allowed <= now)
                        .or_else(|| account.attempts.iter().next())
                        .map(|(k, _)| *k);
                    if let Some(victim) = victim {
                        account.attempts.remove(&victim);
                    }
                }
                let wait = self.delay(0, bad);
                account.attempts.insert(
                    ip,
                    Attempts {
                        count: 0,
                        next_allowed: now + wait,
                    },
                );
                Verdict::Deny {
                    retry_after: wait,
                    kind: DenyKind::Throttled,
                }
            }
            Some(a) if now < a.next_allowed => Verdict::Deny {
                retry_after: a.next_allowed - now,
                kind: DenyKind::Throttled,
            },
            Some(a) => {
                a.count += 1;
                a.next_allowed = now + self.delay(a.count, bad);
                Verdict::Allow
            }
        }
    }

    /// Records a failed attempt from `ip`, at `account` if it exists.
    pub fn record_failure(&self, ip: ClientKey, account: Option<&str>, now: Instant) {
        if !self.config.enabled {
            return;
        }
        let mut state = self.lock();
        let window = self.window();
        let bad = self.is_bad(&mut state, ip, now);
        let mut weight = 1;
        if let Some(username) = account
            && let Some(acct) = self.account_entry(&mut state, username, now)
        {
            let throttled = acct.throttled_until.is_some_and(|t| t > now);
            if throttled && bad {
                weight = 2;
            }
            let cap = self.config.account_failures_to_throttle.max(1) as usize * 2;
            acct.failures.push_back(now);
            prune(&mut acct.failures, now, window, cap);
            if acct.failures.len() >= self.config.account_failures_to_throttle as usize {
                acct.throttled_until = Some(now + window);
            }
        }
        let cap = self.failure_cap();
        let (to_ban, ban_secs, max_ban) = (
            self.config.failures_to_ban as usize,
            self.config.ban_secs,
            self.config.max_ban_secs,
        );
        let Some(s) = self.ip_entry(&mut state, ip, now) else {
            return;
        };
        for _ in 0..weight {
            s.failures.push_back(now);
        }
        prune(&mut s.failures, now, window, cap);
        if s.failures.len() >= to_ban {
            if !s
                .last_offense
                .is_some_and(|t| now.saturating_duration_since(t) < OFFENSE_MEMORY)
            {
                s.offenses = 0;
            }
            let secs = ban_secs
                .saturating_mul(1u64 << s.offenses.min(32))
                .min(max_ban);
            s.banned_until = Some(now + Duration::from_secs(secs));
            s.offenses += 1;
            s.last_offense = Some(now);
            s.failures.clear();
        }
    }

    /// Records a successful login: `ip` is trusted for the account.
    pub fn record_success(&self, username: &str, ip: ClientKey, now: Instant) {
        if !self.config.enabled {
            return;
        }
        let mut state = self.lock();
        let Some(acct) = self.account_entry(&mut state, username, now) else {
            return;
        };
        acct.attempts.remove(&ip);
        acct.trusted.retain(|(k, _)| *k != ip);
        acct.trusted.push((ip, now));
        if acct.trusted.len() > MAX_TRUSTED_PER_ACCOUNT {
            acct.trusted.remove(0);
        }
    }

    /// The account's entry, created if there's room (or room can be made).
    fn account_entry<'a>(
        &self,
        state: &'a mut State,
        username: &str,
        now: Instant,
    ) -> Option<&'a mut AccountState> {
        if !state.accounts.contains_key(username) {
            if state.accounts.len() >= self.config.max_tracked_accounts {
                let victim = state
                    .accounts
                    .iter()
                    .take(EVICTION_SCAN)
                    .find(|(_, a)| !a.throttled_until.is_some_and(|t| t > now))
                    .map(|(k, _)| k.clone())?;
                state.accounts.remove(&victim);
            }
            state
                .accounts
                .insert(username.to_string(), AccountState::default());
        }
        state.accounts.get_mut(username)
    }

    /// Forgets what no longer matters, once a minute.
    fn sweep(&self, state: &mut State, now: Instant) {
        if now.saturating_duration_since(state.last_sweep) < SWEEP_EVERY {
            return;
        }
        state.last_sweep = now;
        let window = self.window();
        let cap = self.failure_cap();
        let (rate, burst) = (self.config.requests_per_second, self.config.request_burst);
        state.ips.retain(|_, s| {
            prune(&mut s.failures, now, window, cap);
            let refilled =
                s.tokens + now.saturating_duration_since(s.refilled).as_secs_f64() * rate >= burst;
            let remembered = s.banned_until.is_some_and(|t| t > now)
                || s.last_offense
                    .is_some_and(|t| now.saturating_duration_since(t) < OFFENSE_MEMORY);
            !(refilled && s.failures.is_empty() && !remembered)
        });
        let trusted_for = Duration::from_secs(self.config.trusted_ip_days * 24 * 60 * 60);
        state.accounts.retain(|_, a| {
            prune(&mut a.failures, now, window, usize::MAX);
            let throttled = a.throttled_until.is_some_and(|t| t > now);
            if !throttled {
                a.throttled_until = None;
                a.attempts.clear();
            }
            a.trusted
                .retain(|(_, t)| now.saturating_duration_since(*t) < trusted_for);
            throttled || !a.failures.is_empty() || !a.trusted.is_empty()
        });
    }
}

#[derive(Deserialize)]
struct UsernameParam {
    username: Option<String>,
}

fn too_many(retry_after: Duration, kind: DenyKind) -> HttpResponse {
    let secs = retry_after.as_secs_f64().ceil().max(1.0) as u64;
    let (type_, message) = match kind {
        DenyKind::RateLimited => ("E_RATE_LIMITED", "too many requests; slow down"),
        DenyKind::Banned => (
            "E_BANNED",
            "too many failed attempts from your network; try again later",
        ),
        DenyKind::Throttled => (
            "E_THROTTLED",
            "this account had many failed login attempts; wait before trying again",
        ),
    };
    HttpResponse::TooManyRequests()
        .insert_header((header::RETRY_AFTER, secs.to_string()))
        .json(json!({ "type": type_, "message": message, "retryAfter": secs }))
}

/// Applies the limits to every request (see the module docs).
pub async fn middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<EitherBody<impl MessageBody>>, Error> {
    let limiter = req
        .app_data::<web::Data<crate::routes::base::AppState>>()
        .map(|state| state.rate_limiter.clone());
    let (Some(limiter), Some(ip)) = (limiter, client_key(&req)) else {
        return Ok(next.call(req).await?.map_into_left_body());
    };
    let now = Instant::now();
    if let Verdict::Deny { retry_after, kind } = limiter.check_request(ip, now) {
        return Ok(req
            .into_response(too_many(retry_after, kind))
            .map_into_right_body());
    }
    let username = web::Query::<UsernameParam>::from_query(req.query_string())
        .ok()
        .and_then(|q| q.into_inner().username);
    if let Some(username) = &username
        && let Verdict::Deny { retry_after, kind } = limiter.check_account(username, ip, now)
    {
        return Ok(req
            .into_response(too_many(retry_after, kind))
            .map_into_right_body());
    }

    let res = next.call(req).await?;
    let now = Instant::now();
    if res.response().extensions().contains::<ServerPassRejected>() {
        limiter.record_failure(ip, None, now);
    }
    let outcome = res.request().extensions().get::<AuthOutcome>().cloned();
    match outcome {
        Some(AuthOutcome::Success { username }) => limiter.record_success(&username, ip, now),
        Some(AuthOutcome::Failure { username, exists }) => {
            limiter.record_failure(ip, exists.then_some(username.as_str()), now)
        }
        None => {}
    }
    Ok(res.map_into_left_body())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> ClientKey {
        ClientKey::from_ip(IpAddr::from([10, 0, 0, n]))
    }

    fn limiter(config: RateLimitConfig) -> RateLimiter {
        RateLimiter::new(config)
    }

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    #[test]
    fn ipv6_counts_by_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(ClientKey::from_ip(a), ClientKey::from_ip(b));
        assert_ne!(ClientKey::from_ip(a), ClientKey::from_ip(c));
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert_eq!(ClientKey::from_ip(mapped), ip(1));
    }

    #[test]
    fn requests_are_rate_limited() {
        let l = limiter(RateLimitConfig {
            requests_per_second: 2.0,
            request_burst: 3.0,
            ..Default::default()
        });
        let t = Instant::now();
        for _ in 0..3 {
            assert_eq!(l.check_request(ip(1), t), Verdict::Allow);
        }
        assert!(matches!(
            l.check_request(ip(1), t),
            Verdict::Deny {
                kind: DenyKind::RateLimited,
                ..
            }
        ));
        // others aren't affected, and the bucket refills
        assert_eq!(l.check_request(ip(2), t), Verdict::Allow);
        assert_eq!(
            l.check_request(ip(1), t + Duration::from_millis(500)),
            Verdict::Allow
        );
    }

    #[test]
    fn failures_ban_an_ip_for_longer_each_time() {
        let l = limiter(RateLimitConfig::default());
        let mut t = Instant::now();
        for round in 0..3u32 {
            for _ in 0..10 {
                l.record_failure(ip(1), None, t);
            }
            let Verdict::Deny { retry_after, kind } = l.check_request(ip(1), t) else {
                panic!("not banned");
            };
            assert_eq!(kind, DenyKind::Banned);
            assert_eq!(retry_after, secs(15 * 60 * (1 << round)));
            t += retry_after;
            assert_eq!(l.check_request(ip(1), t), Verdict::Allow);
        }
        // another IP isn't banned
        assert_eq!(l.check_request(ip(2), t), Verdict::Allow);
    }

    #[test]
    fn throttled_account_makes_new_ips_wait_but_not_its_owner() {
        let l = limiter(RateLimitConfig::default());
        let t = Instant::now();
        // the owner logged in from ip 1
        l.record_success("alice", ip(1), t);
        // an attacker spreads 5 failures over 5 IPs: alice is throttled, but
        // no IP is bad yet
        for n in 10..15 {
            assert_eq!(l.check_account("alice", ip(n), t), Verdict::Allow);
            l.record_failure(ip(n), Some("alice"), t);
        }
        // the owner's IP isn't throttled
        assert_eq!(l.check_account("alice", ip(1), t), Verdict::Allow);
        // a new IP waits 1 s, 5 s, then 10 s (and longer) before its attempts
        let fresh = ip(2);
        let mut now = t;
        for wait in [1, 5, 10, 30, 60, 60] {
            assert_eq!(
                l.check_account("alice", fresh, now),
                Verdict::Deny {
                    retry_after: secs(wait),
                    kind: DenyKind::Throttled
                }
            );
            // too early is refused again, without making it worse
            assert!(matches!(
                l.check_account("alice", fresh, now + secs(wait) / 2),
                Verdict::Deny { .. }
            ));
            now += secs(wait);
            assert_eq!(l.check_account("alice", fresh, now), Verdict::Allow);
        }
        // the owner on a new device: after one wait they're in, and that
        // device isn't throttled again
        let phone = ip(3);
        assert!(matches!(
            l.check_account("alice", phone, now),
            Verdict::Deny { .. }
        ));
        assert_eq!(
            l.check_account("alice", phone, now + secs(1)),
            Verdict::Allow
        );
        l.record_success("alice", phone, now + secs(1));
        assert_eq!(
            l.check_account("alice", phone, now + secs(1)),
            Verdict::Allow
        );
    }

    #[test]
    fn bad_ips_wait_twice_as_long_and_count_double() {
        let l = limiter(RateLimitConfig::default());
        let t = Instant::now();
        for n in 10..15 {
            l.record_failure(ip(n), Some("bob"), t);
        }
        // ip 1 failed elsewhere 3 times: it's bad
        for _ in 0..3 {
            l.record_failure(ip(1), None, t);
        }
        assert_eq!(
            l.check_account("bob", ip(1), t),
            Verdict::Deny {
                retry_after: secs(2),
                kind: DenyKind::Throttled
            }
        );
        assert_eq!(l.check_account("bob", ip(1), t + secs(2)), Verdict::Allow);
        // its failures at bob count double: 3 + 2*3 = 9, then banned at 10+
        for _ in 0..3 {
            l.record_failure(ip(1), Some("bob"), t + secs(2));
        }
        assert_eq!(l.check_request(ip(1), t + secs(2)), Verdict::Allow);
        l.record_failure(ip(1), Some("bob"), t + secs(2));
        assert!(matches!(
            l.check_request(ip(1), t + secs(2)),
            Verdict::Deny {
                kind: DenyKind::Banned,
                ..
            }
        ));
    }

    #[test]
    fn tables_stay_bounded() {
        let l = limiter(RateLimitConfig {
            max_tracked_ips: 100,
            max_tracked_accounts: 10,
            max_ips_per_account: 5,
            ..Default::default()
        });
        let t = Instant::now();
        for n in 0..10_000u32 {
            let k = ClientKey::from_ip(IpAddr::from(n.to_be_bytes()));
            l.check_request(k, t);
            l.record_failure(k, Some(&format!("user{}", n % 50)), t);
            l.check_account("user0", k, t);
        }
        let state = l.lock();
        assert!(state.ips.len() <= 100);
        assert!(state.accounts.len() <= 10);
        assert!(state.accounts.values().all(|a| a.attempts.len() <= 5));
    }

    #[test]
    fn everything_is_forgotten_eventually() {
        let l = limiter(RateLimitConfig::default());
        let t = Instant::now();
        for n in 0..20 {
            l.record_failure(ip(n), Some("carol"), t);
            l.check_request(ip(n), t);
        }
        let later = t + secs(3 * 24 * 60 * 60);
        l.check_request(ip(200), later);
        let state = l.lock();
        assert_eq!(state.ips.len(), 1);
        assert!(state.accounts.is_empty());
    }
}
