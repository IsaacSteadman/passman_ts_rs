package com.firaxite.passman.autofill

import com.firaxite.passman.ServerTransport
import org.json.JSONArray
import java.net.HttpURLConnection
import java.net.URL

/**
 * Digital Asset Links: a site can list the apps that are its own (by package
 * name and signing certificate) at /.well-known/assetlinks.json. Used to tell
 * the user whether linking a login to an app is safe.
 */
object AssetLinks {
    private const val MAX_SITES = 5
    private val RELATIONS = setOf(
        "delegate_permission/common.handle_all_urls",
        "delegate_permission/common.get_login_creds",
    )

    /** The origins among `urls` (https) that list the app as theirs. */
    fun verifiedOrigins(urls: List<String>, app: Target.App): List<String> {
        val origins = urls.mapNotNull { text ->
            try {
                val url = URL(text.trim())
                if (url.protocol.lowercase() == "https") ServerTransport.originOf(url) else null
            } catch (_: Exception) {
                null
            }
        }.distinct().take(MAX_SITES)
        return origins.filter { origin -> runCatching { lists(origin, app) }.getOrDefault(false) }
    }

    private fun lists(origin: String, app: Target.App): Boolean {
        val connection = URL("$origin/.well-known/assetlinks.json").openConnection() as HttpURLConnection
        try {
            // the file must be served without redirects
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 5_000
            connection.readTimeout = 5_000
            if (connection.responseCode != 200) return false
            val text = connection.inputStream.use { ServerTransport.readLimited(it, 256 * 1024) }.decodeToString()
            val statements = JSONArray(text)
            for (i in 0 until statements.length()) {
                val statement = statements.optJSONObject(i) ?: continue
                val relations = statement.optJSONArray("relation") ?: continue
                if ((0 until relations.length()).none { relations.optString(it) in RELATIONS }) continue
                val target = statement.optJSONObject("target") ?: continue
                if (target.optString("namespace") != "android_app") continue
                if (target.optString("package_name") != app.packageName) continue
                val fingerprints = target.optJSONArray("sha256_cert_fingerprints") ?: continue
                if ((0 until fingerprints.length()).any { fingerprints.optString(it).equals(app.certHex, true) })
                    return true
            }
            return false
        } finally {
            connection.disconnect()
        }
    }
}
