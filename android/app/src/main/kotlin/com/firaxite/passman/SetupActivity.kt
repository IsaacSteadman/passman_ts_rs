package com.firaxite.passman

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.util.TypedValue
import android.view.View
import android.view.inputmethod.EditorInfo
import android.webkit.CookieManager
import android.webkit.WebStorage
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.net.HttpURLConnection
import java.net.URL
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import kotlin.concurrent.thread

/**
 * Chooses the server. After connecting it shows the server certificate's key,
 * which the user may choose to trust exclusively (certificate pinning).
 * Changing the server forgets everything kept for the previous one.
 */
class SetupActivity : Activity() {
    private lateinit var serverInput: EditText
    private lateinit var status: TextView
    private lateinit var pin: CheckBox
    private lateinit var useButton: Button
    private var checkedOrigin: String? = null
    private var checkedKey: String? = null

    private fun dp(value: Int) =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value.toFloat(), resources.displayMetrics).toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        secureWindow()
        val settings = ServerSettings(this)
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(48), dp(24), dp(24))
        }
        fun text(value: String, size: Float = 16f) = TextView(this).apply {
            text = value
            setTextSize(TypedValue.COMPLEX_UNIT_SP, size)
            setPadding(0, 0, 0, dp(12))
        }
        column.addView(text("Passman", 28f))
        column.addView(text("Which Passman server do you use?"))
        serverInput = EditText(this).apply {
            id = R.id.server
            hint = "passman.example.com"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            imeOptions = EditorInfo.IME_ACTION_GO or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
            setText(settings.origin ?: "")
            setOnEditorActionListener { _, _, _ -> connect(); true }
        }
        column.addView(serverInput)
        column.addView(Button(this).apply {
            id = R.id.connect
            text = "Connect"
            setOnClickListener { connect() }
        })
        status = text("").apply { id = R.id.status; setPadding(0, dp(12), 0, dp(12)) }
        column.addView(status)
        pin = CheckBox(this).apply {
            id = R.id.pin
            text = "Trust only this certificate key"
            visibility = View.GONE
        }
        column.addView(pin)
        useButton = Button(this).apply {
            id = R.id.use_server
            text = "Use this server"
            visibility = View.GONE
            setOnClickListener { use() }
        }
        column.addView(useButton)
        setContentView(ScrollView(this).apply { addView(column) })
    }

    private fun connect() {
        val origin = ServerSettings.parseOrigin(serverInput.text.toString())
        pin.visibility = View.GONE
        useButton.visibility = View.GONE
        if (origin == null) {
            status.text = if (BuildConfig.DEBUG) "Enter the server's address." else "Enter the server's address (it must use HTTPS)."
            return
        }
        status.text = "Connecting to $origin…"
        thread {
            val result = try {
                val connection = URL("$origin/").openConnection() as HttpURLConnection
                connection.instanceFollowRedirects = false
                connection.connectTimeout = 15_000
                connection.readTimeout = 15_000
                try {
                    connection.responseCode
                    val key = (connection as? HttpsURLConnection)?.serverCertificates
                        ?.firstOrNull()
                        ?.let { ServerTransport.publicKeyFingerprint(it as X509Certificate) }
                    Result.success(key)
                } finally {
                    connection.disconnect()
                }
            } catch (e: Exception) {
                Result.failure(e)
            }
            runOnUiThread {
                result.fold(
                    onSuccess = { key ->
                        checkedOrigin = origin
                        checkedKey = key
                        status.text = if (key != null)
                            "Connected to $origin.\n\nIts certificate key (SHA-256):\n$key\n\n" +
                                "Trusting only this key protects against a forged certificate, but Passman stops " +
                                "connecting if the server's key changes (some servers get a new key with each " +
                                "certificate) until you choose the server again here."
                        else "Connected to $origin (without HTTPS: debug builds only)."
                        pin.isChecked = false
                        pin.visibility = if (key != null) View.VISIBLE else View.GONE
                        useButton.visibility = View.VISIBLE
                    },
                    onFailure = { e -> status.text = "Couldn't connect to $origin: ${e.message ?: e}" },
                )
            }
        }
    }

    private fun use() {
        val origin = checkedOrigin ?: return
        val settings = ServerSettings(this)
        val previous = settings.origin
        if (previous != null && previous != origin) {
            // what's kept on the device belongs to accounts on the previous
            // server
            WebStorage.getInstance().deleteAllData()
            CookieManager.getInstance().removeAllCookies(null)
            UnlockKeys.deleteAll()
        }
        settings.save(origin, if (pin.isChecked) checkedKey else null)
        startActivity(
            Intent(this, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK),
        )
        finish()
    }
}
