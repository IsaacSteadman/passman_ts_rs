package com.firaxite.passmandemo

import android.app.Activity
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

/** A sign-in form like an app's, for trying Passman's autofill. */
class LoginActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val padding = (24 * resources.displayMetrics.density).toInt()
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(padding, padding * 2, padding, padding)
        }
        column.addView(TextView(this).apply { text = "Sign in to Demo"; textSize = 24f })
        val username = EditText(this).apply {
            id = R.id.username
            hint = "Username"
            setAutofillHints(View.AUTOFILL_HINT_USERNAME)
            inputType = InputType.TYPE_CLASS_TEXT
        }
        val password = EditText(this).apply {
            id = R.id.password
            hint = "Password"
            setAutofillHints(View.AUTOFILL_HINT_PASSWORD)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        val code = EditText(this).apply {
            id = R.id.code
            hint = "One-time code"
            setAutofillHints("smsOTPCode")
            inputType = InputType.TYPE_CLASS_NUMBER
        }
        val result = TextView(this).apply { id = R.id.result }
        val signIn = Button(this).apply {
            id = R.id.sign_in
            text = "Sign in"
            setOnClickListener {
                result.text = "Signed in as ${username.text} with ${password.text.length} characters, code ${code.text}"
                // the form is done: Android offers to save what was typed
                getSystemService(AutofillManager::class.java).commit()
            }
        }
        listOf(username, password, code, signIn, result).forEach(column::addView)
        setContentView(column)
    }
}
