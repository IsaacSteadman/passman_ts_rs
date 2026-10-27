package com.firaxite.passman

import android.annotation.SuppressLint
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import android.webkit.PermissionRequest
import android.webkit.RenderProcessGoneDetail
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import java.io.ByteArrayInputStream

/**
 * The web view the app's pages run in. They come from the APK's assets (as
 * https://appassets.androidplatform.net/…, so they get a secure context), and
 * the view loads nothing else: no other page, nothing from the network (the
 * pages' requests to the server go through the Bridge), no files. Keyboards
 * are asked not to learn from what's typed. (Android's autofill service still
 * sees its fields, as the web view tells it about them whatever the view's
 * importantForAutofill says; Passman's own service ignores them.)
 */
@SuppressLint("SetJavaScriptEnabled", "ViewConstructor")
class PassmanWebView(private val host: PageHost) : WebView(host) {
    private val assets = WebViewAssetLoader.Builder()
        .addPathHandler("/", WebViewAssetLoader.AssetsPathHandler(host))
        .build()

    init {
        setWebContentsDebuggingEnabled(BuildConfig.DEBUG)
        with(settings) {
            javaScriptEnabled = true
            domStorageEnabled = true
            allowFileAccess = false
            allowContentAccess = false
            blockNetworkLoads = true
            setGeolocationEnabled(false)
            setSupportMultipleWindows(false)
            javaScriptCanOpenWindowsAutomatically = false
            saveFormData = false
        }
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER))
            throw IllegalStateException("This device's WebView is too old for Passman; update Android System WebView.")
        WebViewCompat.addWebMessageListener(this, "passmanNative", setOf(ORIGIN), Bridge(host))
        webViewClient = Client()
        webChromeClient = ChromeClient()
    }

    fun load(page: String) = loadUrl("$ORIGIN/$page")

    override fun onCreateInputConnection(outAttrs: EditorInfo): InputConnection? {
        val connection = super.onCreateInputConnection(outAttrs)
        outAttrs.imeOptions = outAttrs.imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        return connection
    }

    private inner class Client : WebViewClient() {
        override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse =
            assets.shouldInterceptRequest(request.url)
                ?: WebResourceResponse(
                    "text/plain", "utf-8", 403, "Forbidden", emptyMap(),
                    ByteArrayInputStream(ByteArray(0)),
                )

        override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
            val url = request.url
            if (url.scheme == "https" && url.host == DOMAIN) return false
            // links in the vault open in the apps for them, when tapped
            if (request.hasGesture() && url.scheme?.lowercase() in EXTERNAL_SCHEMES) {
                try {
                    host.startActivity(
                        Intent(Intent.ACTION_VIEW, url).addCategory(Intent.CATEGORY_BROWSABLE),
                    )
                } catch (_: ActivityNotFoundException) {
                    // nothing handles it
                }
            }
            return true
        }

        override fun onRenderProcessGone(view: WebView, detail: RenderProcessGoneDetail): Boolean {
            // the page is gone (and with it the unlocked vault): start again
            host.recreate()
            return true
        }
    }

    private inner class ChromeClient : WebChromeClient() {
        override fun onPermissionRequest(request: PermissionRequest) {
            val camera = request.origin.toString().trimEnd('/') == ORIGIN &&
                request.resources.all { it == PermissionRequest.RESOURCE_VIDEO_CAPTURE }
            if (!camera) {
                request.deny()
                return
            }
            host.withCameraPermission { granted ->
                if (granted) request.grant(arrayOf(PermissionRequest.RESOURCE_VIDEO_CAPTURE)) else request.deny()
            }
        }

        override fun onShowFileChooser(
            webView: WebView,
            filePathCallback: ValueCallback<Array<Uri>>,
            fileChooserParams: FileChooserParams,
        ): Boolean {
            host.startForResult(fileChooserParams.createIntent()) { code, data ->
                filePathCallback.onReceiveValue(FileChooserParams.parseResult(code, data))
            }
            return true
        }
    }

    companion object {
        const val DOMAIN = WebViewAssetLoader.DEFAULT_DOMAIN
        const val ORIGIN = "https://$DOMAIN"
        private val EXTERNAL_SCHEMES = setOf("http", "https", "mailto", "tel", "sms")
    }
}
