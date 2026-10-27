package com.firaxite.passman

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle

/** The web app (frontend/index.html), from the APK. */
class MainActivity : PageHost() {
    override val page = "index.html"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (ServerSettings(this).origin == null) {
            startActivity(Intent(this, SetupActivity::class.java))
            finish()
            return
        }
        showPage()
    }

    override fun changeServer() {
        AlertDialog.Builder(this)
            .setTitle("Change server?")
            .setMessage(
                "Choosing another server forgets the accounts remembered on this device, " +
                    "their vaults and biometric unlock. Changes not uploaded yet are lost.",
            )
            .setPositiveButton("Continue") { _, _ ->
                startActivity(Intent(this, SetupActivity::class.java))
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
}
