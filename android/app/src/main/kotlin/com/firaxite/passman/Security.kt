package com.firaxite.passman

import android.app.Activity
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.view.WindowManager
import android.widget.Toast

/**
 * Keeps an activity's window to itself: no screenshots or screen recording of
 * it (nor of its thumbnail in the recent apps), and no other app's window
 * drawn over it to trick the user into tapping something.
 */
fun Activity.secureWindow() {
    window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) window.setHideOverlayWindows(true)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) setRecentsScreenshotEnabled(false)
}

/**
 * Copies text marked as sensitive, so Android doesn't show it in its
 * clipboard preview (and keyboards don't suggest it), and clears it again
 * after a while.
 */
object SecureClipboard {
    const val CLEAR_AFTER_MS = 45_000L
    private const val LABEL = "Passman"
    private val handler = Handler(Looper.getMainLooper())
    private var pendingClear: Runnable? = null

    fun copy(context: Context, text: String) {
        val clipboard = context.getSystemService(ClipboardManager::class.java)
        val clip = ClipData.newPlainText(LABEL, text)
        clip.description.extras = PersistableBundle().apply {
            putBoolean(
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) ClipDescription.EXTRA_IS_SENSITIVE
                else "android.content.extra.IS_SENSITIVE",
                true,
            )
        }
        clipboard.setPrimaryClip(clip)
        // Android 13 and later confirm copies themselves
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU)
            Toast.makeText(context, "Copied; cleared in ${CLEAR_AFTER_MS / 1000} seconds", Toast.LENGTH_SHORT).show()

        pendingClear?.let(handler::removeCallbacks)
        val clear = Runnable {
            pendingClear = null
            // in the background Android doesn't say what's on the clipboard;
            // when it does, leave something copied since alone
            val label = clipboard.primaryClipDescription?.label
            if (label == null || label == LABEL) clipboard.clearPrimaryClip()
        }
        pendingClear = clear
        handler.postDelayed(clear, CLEAR_AFTER_MS)
    }
}
