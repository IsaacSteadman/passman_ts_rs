package com.firaxite.passman

import android.Manifest
import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import org.json.JSONObject

/** An activity showing one of the app's pages (see PassmanWebView). */
abstract class PageHost : Activity() {
    protected lateinit var web: PassmanWebView
    protected abstract val page: String

    private val results = HashMap<Int, (Int, Intent?) -> Unit>()
    private var nextRequest = 1
    private var cameraCallback: ((Boolean) -> Unit)? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        secureWindow()
    }

    protected fun showPage() {
        web = PassmanWebView(this)
        setContentView(web)
        web.load(page)
    }

    /** Calls from the page the Bridge doesn't handle itself; false if
     *  `method` isn't one. */
    open fun handle(method: String, params: JSONObject, reply: Reply): Boolean = false

    /** "Change server" in the page. */
    open fun changeServer() {}

    fun startForResult(intent: Intent, done: (Int, Intent?) -> Unit) {
        val code = nextRequest++
        results[code] = done
        try {
            @Suppress("DEPRECATION")
            startActivityForResult(intent, code)
        } catch (_: ActivityNotFoundException) {
            results.remove(code)
            done(RESULT_CANCELED, null)
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val done = results.remove(requestCode)
        if (done != null) done(resultCode, data)
        else @Suppress("DEPRECATION") super.onActivityResult(requestCode, resultCode, data)
    }

    fun withCameraPermission(done: (Boolean) -> Unit) {
        if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            done(true)
            return
        }
        cameraCallback = done
        requestPermissions(arrayOf(Manifest.permission.CAMERA), CAMERA_REQUEST)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != CAMERA_REQUEST) return
        cameraCallback?.invoke(grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED)
        cameraCallback = null
    }

    override fun onDestroy() {
        if (::web.isInitialized) web.destroy()
        super.onDestroy()
    }

    private companion object {
        const val CAMERA_REQUEST = 1_000_000
    }
}
