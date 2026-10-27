package com.firaxite.passman

import android.content.Context
import java.net.URL

/**
 * The Passman server this install uses: one per install, chosen in
 * SetupActivity. Optionally, only the certificate key the server had then is
 * trusted (see ServerTransport).
 */
class ServerSettings(context: Context) {
    private val prefs = context.getSharedPreferences("server", Context.MODE_PRIVATE)

    /** The server's origin, e.g. "https://passman.example.com". */
    val origin: String? get() = prefs.getString(ORIGIN, null)

    /** The SHA-256 of the server certificate's public key (SubjectPublicKeyInfo)
     *  that is the only one trusted, as colon-separated hex; null to trust any
     *  certificate Android trusts. */
    val pinnedKey: String? get() = prefs.getString(PINNED_KEY, null)

    fun save(origin: String, pinnedKey: String?) {
        prefs.edit().putString(ORIGIN, origin).putString(PINNED_KEY, pinnedKey).apply()
    }

    companion object {
        private const val ORIGIN = "origin"
        private const val PINNED_KEY = "pinnedKey"

        /** The origin of an address the user typed (which may lack "https://"),
         *  or null if it isn't one; plain HTTP only in debug builds. */
        fun parseOrigin(text: String): String? {
            val trimmed = text.trim().trimEnd('/')
            if (trimmed.isEmpty()) return null
            val withScheme = if (Regex("^[a-zA-Z][a-zA-Z0-9+.-]*://").containsMatchIn(trimmed)) trimmed else "https://$trimmed"
            return try {
                val url = URL(withScheme)
                val scheme = url.protocol.lowercase()
                if (scheme != "https" && !(scheme == "http" && BuildConfig.DEBUG)) return null
                if (url.host.isNullOrEmpty()) return null
                val port = if (url.port == -1 || url.port == url.defaultPort) "" else ":${url.port}"
                "$scheme://${url.host.lowercase()}$port"
            } catch (_: Exception) {
                null
            }
        }
    }
}
