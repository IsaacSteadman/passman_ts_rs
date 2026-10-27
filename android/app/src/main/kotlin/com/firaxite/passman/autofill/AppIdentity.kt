package com.firaxite.passman.autofill

import android.content.Context
import android.content.pm.PackageManager
import android.util.Base64
import com.firaxite.passman.R
import com.firaxite.passman.sha256
import com.firaxite.passman.toColonHex
import org.json.JSONObject

/** Who asked to fill: a web page (as told by a browser Passman trusts) or an
 *  app, identified by its package name and signing certificate. */
sealed class Target {
    data class Web(val url: String) : Target()
    data class App(val packageName: String, val certSha256: ByteArray, val label: String) : Target() {
        /** As saved in logins: base64url with padding (frontend/logins.ts). */
        val certHash: String get() = Base64.encodeToString(certSha256, Base64.URL_SAFE or Base64.NO_WRAP)
        val certHex: String get() = certSha256.toColonHex()
    }

    fun toJson(): JSONObject = when (this) {
        is Web -> JSONObject().put("kind", "web").put("url", url)
        is App -> JSONObject().put("kind", "app").put("packageName", packageName)
            .put("certHash", certHash).put("label", label)
    }
}

object AppIdentity {
    /** The SHA-256 of the app's signing certificate, or null if it can't be
     *  told (not installed, not visible to Passman, or several signers). */
    fun certSha256(context: Context, packageName: String): ByteArray? = try {
        val info = context.packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val signers = info.signingInfo?.apkContentsSigners
        if (signers == null || signers.size != 1) null else signers[0].toByteArray().sha256()
    } catch (_: PackageManager.NameNotFoundException) {
        null
    }

    fun label(context: Context, packageName: String): String = try {
        val pm = context.packageManager
        pm.getApplicationLabel(pm.getApplicationInfo(packageName, 0)).toString()
    } catch (_: PackageManager.NameNotFoundException) {
        packageName
    }

    private var browsers: Map<String, Set<String>>? = null

    /** Whether the app is a browser Passman takes the word of for which site
     *  is open (res/raw/browsers.json, see scripts/update-browsers.mjs). */
    fun isTrustedBrowser(context: Context, packageName: String, certSha256: ByteArray): Boolean {
        val known = browsers ?: context.resources.openRawResource(R.raw.browsers).use { stream ->
            val json = JSONObject(stream.readBytes().decodeToString())
            json.keys().asSequence().associateWith { name ->
                json.getJSONArray(name).let { list -> (0 until list.length()).map(list::getString).toSet() }
            }
        }.also { browsers = it }
        return known[packageName]?.contains(certSha256.toColonHex()) == true
    }

    /** What's asking to fill the form described by `form`, if it can be
     *  told. */
    fun target(context: Context, form: ParsedForm): Target? {
        val packageName = form.packageName ?: return null
        if (packageName == context.packageName) return null
        val cert = certSha256(context, packageName) ?: return null
        val domain = form.webDomain
        if (domain != null && isTrustedBrowser(context, packageName, cert)) {
            val scheme = form.webScheme?.lowercase() ?: "https"
            if (scheme != "https" && scheme != "http") return null
            return Target.Web("$scheme://$domain")
        }
        // a web page shown in an app is the app's: its logins aren't the
        // site's
        return Target.App(packageName, cert, label(context, packageName))
    }
}
