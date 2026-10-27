package com.firaxite.passman

import android.content.Intent
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.webkit.WebView
import androidx.webkit.JavaScriptReplyProxy
import androidx.webkit.WebMessageCompat
import androidx.webkit.WebViewCompat
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.Executors
import javax.crypto.AEADBadTagException

/** Answers one call from a page (on any thread). */
class Reply(private val id: Int, private val proxy: JavaScriptReplyProxy) {
    private val main = Handler(Looper.getMainLooper())

    fun ok(result: Any? = null) = send(JSONObject().put("id", id).put("result", result ?: JSONObject.NULL))

    fun error(message: String, kind: String = "error") = send(
        JSONObject().put("id", id).put("error", JSONObject().put("message", message).put("kind", kind)),
    )

    fun fail(e: Throwable) = when (e) {
        is TransportException -> error(e.message ?: "", e.kind)
        is UnlockKeyException -> error(e.message ?: "", e.kind)
        else -> error(e.message ?: e.toString())
    }

    private fun send(message: JSONObject) = main.post { proxy.postMessage(message.toString()) }
}

/**
 * What the pages ask the app for (see frontend/nativeApp.ts). Only the app's
 * own pages, in the main frame, can call it: the listener is only added for
 * their origin, and that is checked again here.
 */
class Bridge(private val host: PageHost) : WebViewCompat.WebMessageListener {
    private val background = Executors.newCachedThreadPool()

    override fun onPostMessage(
        view: WebView,
        message: WebMessageCompat,
        sourceOrigin: Uri,
        isMainFrame: Boolean,
        replyProxy: JavaScriptReplyProxy,
    ) {
        if (!isMainFrame || sourceOrigin.toString().trimEnd('/') != PassmanWebView.ORIGIN) return
        val request = JSONObject(message.data ?: return)
        val reply = Reply(request.getInt("id"), replyProxy)
        try {
            handle(request.getString("method"), request.optJSONObject("params") ?: JSONObject(), reply)
        } catch (e: Exception) {
            reply.fail(e)
        }
    }

    private fun inBackground(reply: Reply, work: () -> Any?) = background.execute {
        try {
            reply.ok(work())
        } catch (e: Exception) {
            reply.fail(e)
        }
    }

    private fun handle(method: String, params: JSONObject, reply: Reply) {
        val settings = ServerSettings(host)
        when (method) {
            "config" -> reply.ok(
                JSONObject().put("server", settings.origin).put("pinnedKey", settings.pinnedKey ?: JSONObject.NULL),
            )

            "fetch" -> {
                val origin = settings.origin ?: throw TransportException("No server is set up.", "error")
                val headers = params.getJSONArray("headers").let { list ->
                    (0 until list.length()).map { list.getJSONArray(it).let { h -> h.getString(0) to h.getString(1) } }
                }
                val body = if (params.isNull("body")) null else params.getString("body").fromBase64Url()
                inBackground(reply) {
                    val result = ServerTransport(origin, settings.pinnedKey)
                        .request(params.getString("url"), params.getString("method"), headers, body)
                    JSONObject()
                        .put("status", result.status)
                        .put("statusText", result.statusText)
                        .put("headers", JSONArray(result.headers.map { JSONArray(listOf(it.first, it.second)) }))
                        .put("body", result.body.toBase64Url())
                }
            }

            "biometricsAvailable" -> reply.ok(UnlockKeys.available(host))

            "protect" -> {
                val cipher = UnlockKeys.encryptCipher(host, params.getString("alias"))
                UnlockKeys.authenticate(host, "Turn on biometric unlock", cipher) { result ->
                    result.fold(
                        onSuccess = { unlocked ->
                            unlocked.updateAAD(params.getString("aad").toByteArray())
                            val ciphertext = unlocked.doFinal(params.getString("secret").fromBase64Url())
                            reply.ok(
                                JSONObject()
                                    .put("iv", unlocked.iv.toBase64Url())
                                    .put("ciphertext", ciphertext.toBase64Url()),
                            )
                        },
                        onFailure = reply::fail,
                    )
                }
            }

            "unprotect" -> {
                val cipher = UnlockKeys.decryptCipher(params.getString("alias"), params.getString("iv").fromBase64Url())
                UnlockKeys.authenticate(host, "Unlock Passman", cipher) { result ->
                    result.fold(
                        onSuccess = { unlocked ->
                            try {
                                unlocked.updateAAD(params.getString("aad").toByteArray())
                                val secret = unlocked.doFinal(params.getString("ciphertext").fromBase64Url())
                                reply.ok(JSONObject().put("secret", secret.toBase64Url()))
                            } catch (_: AEADBadTagException) {
                                reply.error("The keys stored for biometric unlock couldn't be decrypted.")
                            }
                        },
                        onFailure = reply::fail,
                    )
                }
            }

            "removeKey" -> {
                UnlockKeys.delete(params.getString("alias"))
                reply.ok()
            }

            "copy" -> {
                SecureClipboard.copy(host, params.getString("text"))
                reply.ok()
            }

            "saveFile" -> {
                val text = params.getString("text")
                val intent = Intent(Intent.ACTION_CREATE_DOCUMENT)
                    .addCategory(Intent.CATEGORY_OPENABLE)
                    .setType(params.getString("type"))
                    .putExtra(Intent.EXTRA_TITLE, params.getString("name"))
                host.startForResult(intent) { _, data ->
                    val uri = data?.data
                    if (uri == null) {
                        reply.error("cancelled", "cancelled")
                        return@startForResult
                    }
                    inBackground(reply) {
                        host.contentResolver.openOutputStream(uri, "wt")!!.use { it.write(text.toByteArray()) }
                        null
                    }
                }
            }

            "changeServer" -> {
                host.changeServer()
                reply.ok()
            }

            else -> if (!host.handle(method, params, reply)) reply.error("Unknown call $method")
        }
    }
}
