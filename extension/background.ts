// Locks the extension (forgets the unlocked session) when its time is up or
// the computer is locked. Everything else happens in the popup.

import { ext } from "./browserApi";
import { LOCK_ALARM, clearSession } from "./session";

ext.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === LOCK_ALARM) void clearSession();
});

// not in Safari
ext.idle?.onStateChanged.addListener((state) => {
  if (state === "locked") void clearSession();
});
