// Locks the vault after a period without user input, and (optionally) as soon
// as the app is hidden. The settings belong to this device: they're kept in
// localStorage and never synced with the account.

export interface LockSettings {
  /** Minutes without input before locking; null to never lock when idle. */
  idleMinutes: number | null;
  /** Lock when the app is hidden (switching apps, turning the screen off). */
  lockWhenHidden: boolean;
}

export const DEFAULT_LOCK_SETTINGS: LockSettings = {
  idleMinutes: 5,
  lockWhenHidden: true,
};

const STORAGE_KEY = "passman.lockSettings";

export function loadLockSettings(): LockSettings {
  try {
    const parsed: unknown = JSON.parse(
      localStorage.getItem(STORAGE_KEY) ?? "null",
    );
    if (parsed != null && typeof parsed === "object") {
      const { idleMinutes, lockWhenHidden } = parsed as Partial<LockSettings>;
      return {
        idleMinutes:
          idleMinutes === null ||
          (typeof idleMinutes === "number" && idleMinutes > 0)
            ? idleMinutes
            : DEFAULT_LOCK_SETTINGS.idleMinutes,
        lockWhenHidden:
          typeof lockWhenHidden === "boolean"
            ? lockWhenHidden
            : DEFAULT_LOCK_SETTINGS.lockWhenHidden,
      };
    }
  } catch {
    // unreadable: use the defaults
  }
  return { ...DEFAULT_LOCK_SETTINGS };
}

export function saveLockSettings(settings: LockSettings): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
}

export interface AutoLock {
  /** Starts watching (after unlocking). */
  start(): void;
  /** Stops watching (after locking or logging out). */
  stop(): void;
  /** Applies changed settings. */
  settingsChanged(): void;
  /** Runs `task` without locking when the app is hidden: system prompts such
   *  as the passkey sheet may hide it. */
  suspendWhile<T>(task: () => Promise<T>): Promise<T>;
}

const ACTIVITY_EVENTS = [
  "pointerdown",
  "keydown",
  "wheel",
  "touchstart",
  "scroll",
  "input",
];

/** `lock` returns false if it couldn't lock right now; the idle period then
 *  starts again. */
export function initAutoLock(lock: () => boolean): AutoLock {
  let running = false;
  let lastActivity = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let suspended = 0;

  function onActivity(): void {
    lastActivity = Date.now();
  }

  function fire(): void {
    if (!running) return;
    if (lock()) {
      stop();
    } else {
      lastActivity = Date.now();
      schedule();
    }
  }

  /** Locks if the idle time has passed, else checks again when it would.
   *  Timers may be delayed while the app is in the background, so this also
   *  runs when it comes back. */
  function schedule(): void {
    clearTimeout(timer);
    if (!running) return;
    const { idleMinutes } = loadLockSettings();
    if (idleMinutes == null) return;
    const remaining = lastActivity + idleMinutes * 60_000 - Date.now();
    if (remaining <= 0) fire();
    else timer = setTimeout(schedule, remaining);
  }

  function onVisibilityChange(): void {
    if (!running) return;
    if (document.visibilityState === "hidden") {
      if (loadLockSettings().lockWhenHidden && suspended === 0) fire();
    } else {
      schedule();
    }
  }

  function onPageHide(): void {
    if (running && loadLockSettings().lockWhenHidden && suspended === 0) fire();
  }

  function start(): void {
    if (running) return;
    running = true;
    lastActivity = Date.now();
    for (const name of ACTIVITY_EVENTS)
      document.addEventListener(name, onActivity, {
        capture: true,
        passive: true,
      });
    document.addEventListener("visibilitychange", onVisibilityChange);
    window.addEventListener("pagehide", onPageHide);
    schedule();
  }

  function stop(): void {
    running = false;
    clearTimeout(timer);
    for (const name of ACTIVITY_EVENTS)
      document.removeEventListener(name, onActivity, { capture: true });
    document.removeEventListener("visibilitychange", onVisibilityChange);
    window.removeEventListener("pagehide", onPageHide);
  }

  return {
    start,
    stop,
    settingsChanged: schedule,
    async suspendWhile(task) {
      suspended++;
      try {
        return await task();
      } finally {
        suspended--;
        // hidden meanwhile and should lock: do it now
        if (document.visibilityState === "hidden") onVisibilityChange();
      }
    },
  };
}
