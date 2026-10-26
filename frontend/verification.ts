// Verifying other users' sharing identities, so the server can't swap in
// its own: in person by scanning each other's QR codes, or by reading a
// safety number to each other (e.g. on a call). Nothing shown is secret: a QR
// code holds a username and the fingerprint (a hash) of their public
// identity.

import jsQR from "jsqr";
import qrcode from "qrcode-generator";
import type { SharingContact } from "./PassTable";
import { formatFingerprint, safetyNumber } from "./sharingCrypto";

const QR_PREFIX = "passman:id:v1:";

/** What a user's QR code says. Usernames can't contain ':'. */
export function qrPayload(username: string, fingerprint: string): string {
  return `${QR_PREFIX}${username}:${fingerprint}`;
}

export function parseQrPayload(
  text: string,
): { username: string; fingerprint: string } | null {
  if (!text.startsWith(QR_PREFIX)) return null;
  const rest = text.slice(QR_PREFIX.length);
  const at = rest.lastIndexOf(":");
  if (at <= 0) return null;
  return { username: rest.slice(0, at), fingerprint: rest.slice(at + 1) };
}

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className = "",
  text?: string,
): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (className) e.className = className;
  if (text != null) e.textContent = text;
  return e;
}

function button(label: string, primary = false): HTMLButtonElement {
  const b = el(
    "button",
    primary ? "pm-btn pm-btn-primary" : "pm-btn pm-btn-ghost",
    label,
  );
  b.type = "button";
  return b;
}

/** How to close each dialog open now. */
const openDialogs = new Set<() => void>();

/** Closes any verification dialog (stopping the camera), e.g. on locking. */
export function closeVerificationDialogs(): void {
  for (const close of [...openDialogs]) close();
}

/** Opens a dialog; returns its body element and a function closing it.
 *  `onClose` runs however it closes. */
function modal(
  title: string,
  onClose: () => void = () => {},
): { body: HTMLElement; footer: HTMLElement; close: () => void } {
  const backdrop = el("div", "pm-backdrop");
  const dialog = el("div", "pm-modal pm-verify-modal");
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-label", title);
  const body = el("div");
  const footer = el("div", "pm-modal-footer");
  const close = () => {
    openDialogs.delete(close);
    backdrop.remove();
    onClose();
  };
  openDialogs.add(close);
  const closeButton = button("Close");
  closeButton.addEventListener("click", close);
  footer.append(closeButton);
  backdrop.addEventListener("click", (e) => {
    if (e.target === backdrop) close();
  });
  dialog.append(el("h3", "", title), body, footer);
  backdrop.append(dialog);
  document.body.append(backdrop);
  return { body, footer, close };
}

/** An image of the user's QR code, for others to scan. */
function qrImage(username: string, fingerprint: string): HTMLImageElement {
  const qr = qrcode(0, "M");
  qr.addData(qrPayload(username, fingerprint));
  qr.make();
  const img = el("img", "pm-qr");
  img.src = qr.createDataURL(6, 4);
  img.alt = `Sharing code of ${username}`;
  return img;
}

/** Shows the user's own QR code and fingerprint. */
export function showMyCode(username: string, fingerprint: string): void {
  const { body } = modal("Your sharing code");
  body.append(
    el(
      "p",
      "pm-device-status",
      "Let the person you're sharing with scan this with Passman (Verify someone). It only identifies you; it doesn't give access to anything.",
    ),
    qrImage(username, fingerprint),
    el("p", "pm-fingerprint", formatFingerprint(fingerprint)),
  );
}

/** Reads a QR code from an image file. */
async function decodeImage(file: Blob): Promise<string | null> {
  const bitmap = await createImageBitmap(file);
  const canvas = el("canvas");
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  const ctx = canvas.getContext("2d")!;
  ctx.drawImage(bitmap, 0, 0);
  const image = ctx.getImageData(0, 0, canvas.width, canvas.height);
  return jsQR(image.data, image.width, image.height)?.data ?? null;
}

/** Scans QR codes with the camera until `onCode` returns true; returns a
 *  function stopping it. */
async function scanWithCamera(
  video: HTMLVideoElement,
  onCode: (text: string) => boolean,
): Promise<() => void> {
  const stream = await navigator.mediaDevices.getUserMedia({
    video: { facingMode: "environment" },
  });
  video.srcObject = stream;
  video.setAttribute("playsinline", "");
  await video.play();
  const canvas = el("canvas");
  const ctx = canvas.getContext("2d", { willReadFrequently: true })!;
  let stopped = false;
  const stop = () => {
    stopped = true;
    for (const track of stream.getTracks()) track.stop();
    video.srcObject = null;
  };
  const tick = () => {
    if (stopped) return;
    if (video.readyState >= video.HAVE_ENOUGH_DATA) {
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      ctx.drawImage(video, 0, 0);
      const image = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(image.data, image.width, image.height);
      if (code && onCode(code.data)) {
        stop();
        return;
      }
    }
    requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
  return stop;
}

export interface VerifyOptions {
  me: { username: string; fingerprint: string };
  /** The user to verify and the fingerprint the server gave for them. */
  target: { username: string; fingerprint: string };
  /** Stores the verification (in the user's own vault). */
  onVerified: (contact: SharingContact) => Promise<void>;
}

/** The dialog verifying `target`: by scanning their code, or by comparing
 *  the safety number. */
export function verifyUser({ me, target, onVerified }: VerifyOptions): void {
  let stopCamera: (() => void) | null = null;
  const { body, close } = modal(`Verify ${target.username}`, () =>
    stopCamera?.(),
  );
  const result = el("div", "pm-verify-result");
  result.setAttribute("role", "status");

  const done = async (method: SharingContact["method"]) => {
    await onVerified({
      fingerprint: target.fingerprint,
      method,
      verifiedAt: new Date().toISOString(),
    });
    result.className = "pm-verify-result pm-verify-ok";
    result.replaceChildren(
      el(
        "p",
        "",
        `✓ ${target.username} is verified. They should verify you too:`,
      ),
    );
    const showMine = button("Show my code", true);
    showMine.addEventListener("click", () => {
      close();
      showMyCode(me.username, me.fingerprint);
    });
    result.append(showMine);
  };
  const mismatch = (what: string) => {
    result.className = "pm-verify-result pm-verify-bad";
    result.textContent = `⚠ ${what} doesn't match the identity the server gave for ${target.username}. Don't share with them for now: someone may be intercepting. Check you're scanning the right person, and that they've set up sharing on this server.`;
  };
  const checkCode = (text: string): boolean => {
    const scanned = parseQrPayload(text);
    if (scanned == null) {
      result.className = "pm-verify-result";
      result.textContent = "That isn't a Passman sharing code.";
      return false;
    }
    if (
      scanned.username === target.username &&
      scanned.fingerprint === target.fingerprint
    )
      void done("qr");
    else mismatch("The scanned code");
    return true;
  };

  // ── In person: scan their code ────────────────────────────────────────────
  const scanSection = el("div", "pm-device-subsection");
  scanSection.append(
    el(
      "p",
      "pm-device-status",
      `In person: scan the code ${target.username} shows under Shared Vaults → Show my code.`,
    ),
  );
  const video = el("video", "pm-qr-video");
  video.hidden = true;
  video.muted = true;
  const cameraButton = button("Scan with camera", true);
  cameraButton.addEventListener("click", async () => {
    try {
      video.hidden = false;
      stopCamera = await scanWithCamera(video, (text) => {
        const finished = checkCode(text);
        if (finished) video.hidden = true;
        return finished;
      });
    } catch (e) {
      video.hidden = true;
      result.className = "pm-verify-result";
      result.textContent = `Couldn't use the camera (${e}). Scan a photo of their code instead.`;
    }
  });
  const photoInput = el("input");
  photoInput.type = "file";
  photoInput.accept = "image/*";
  photoInput.name = "qr-photo";
  photoInput.className = "pm-visually-hidden";
  photoInput.addEventListener("change", async () => {
    const file = photoInput.files?.[0];
    photoInput.value = "";
    if (!file) return;
    const text = await decodeImage(file).catch(() => null);
    if (text == null) {
      result.className = "pm-verify-result";
      result.textContent = "No QR code found in that picture.";
    } else checkCode(text);
  });
  const photoButton = button("Scan a photo");
  photoButton.addEventListener("click", () => photoInput.click());
  const actions = el("div", "pm-device-actions");
  actions.append(cameraButton, photoButton, photoInput);
  scanSection.append(actions, video);

  // ── Remotely: compare the safety number ───────────────────────────────────
  const numberSection = el("div", "pm-device-subsection");
  const number = safetyNumber(
    me.username,
    me.fingerprint,
    target.username,
    target.fingerprint,
  );
  numberSection.append(
    el(
      "p",
      "pm-device-status",
      `Remotely: on a call (not by message), read this number to ${target.username}. They see the same number when verifying you only if neither of you is being intercepted.`,
    ),
    el("p", "pm-safety-number", number),
  );
  const matches = button("It matches", true);
  matches.addEventListener("click", () => void done("safety-number"));
  const differs = button("It's different");
  differs.addEventListener("click", () => mismatch("The safety number"));
  const numberActions = el("div", "pm-device-actions");
  numberActions.append(matches, differs);
  numberSection.append(numberActions);

  body.append(
    el(
      "p",
      "pm-field-hint",
      `Fingerprint the server gave for ${target.username}: ${formatFingerprint(target.fingerprint)}`,
    ),
    scanSection,
    numberSection,
    result,
  );
}
