package com.firaxite.passman.autofill

import android.app.PendingIntent
import android.content.Intent
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.widget.RemoteViews
import com.firaxite.passman.R
import com.firaxite.passman.ServerSettings
import java.util.UUID

/** What to save, kept in memory only: the password never leaves the app's
 *  process (not even in an Intent). */
class SaveData(val target: Target, val username: String, val password: String)

object PendingSaves {
    private val saves = HashMap<String, SaveData>()

    @Synchronized
    fun put(data: SaveData): String = UUID.randomUUID().toString().also { saves[it] = data }

    @Synchronized
    fun get(token: String): SaveData? = saves[token]

    @Synchronized
    fun remove(token: String) {
        saves.remove(token)
    }
}

/**
 * Android's autofill: offers "Fill with Passman" in login forms, which opens
 * AutofillActivity (nothing is read from the vault until the user unlocks
 * there), and offers to save what was typed when a form is sent.
 */
class PassmanAutofillService : AutofillService() {
    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        val form = StructureParser.parse(request.fillContexts.last().structure)
        val target = if (form.fillIds.isEmpty() || ServerSettings(this).origin == null) null
        else AppIdentity.target(this, form)
        if (target == null) {
            callback.onSuccess(null)
            return
        }
        val intent = Intent(this, AutofillActivity::class.java).putExtra(AutofillActivity.MODE, AutofillActivity.FILL)
        // mutable: Android adds the form's structure to it
        val pending = PendingIntent.getActivity(
            this, request.id, intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_CANCEL_CURRENT,
        )
        // one locked dataset: what AutofillActivity returns replaces it, and
        // is filled straight away
        val locked = Dataset.Builder(presentation())
        @Suppress("DEPRECATION")
        for (id in form.fillIds) locked.setValue(id, null)
        locked.setAuthentication(pending.intentSender)
        val response = FillResponse.Builder().addDataset(locked.build())
        val passwords = form.newPasswords.ifEmpty { form.passwords }
        if (passwords.isNotEmpty()) {
            var type = SaveInfo.SAVE_DATA_TYPE_PASSWORD
            if (form.username != null) type = type or SaveInfo.SAVE_DATA_TYPE_USERNAME
            val save = SaveInfo.Builder(type, passwords.map { it.id }.toTypedArray())
                .setFlags(SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE)
            form.username?.let { save.setOptionalIds(arrayOf(it.id)) }
            response.setSaveInfo(save.build())
        }
        callback.onSuccess(response.build())
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val forms = request.fillContexts.map { StructureParser.parse(it.structure) }
        val form = forms.last()
        val password = form.newPasswords.ifEmpty { form.passwords }
            .firstNotNullOfOrNull { it.value?.takeIf(String::isNotEmpty) }
        val target = AppIdentity.target(this, form)
        if (password == null || target == null) {
            callback.onFailure("Passman can't save this login.")
            return
        }
        // the username may have been on an earlier screen
        val username = forms.asReversed()
            .firstNotNullOfOrNull { it.username?.value?.trim()?.takeIf(String::isNotEmpty) } ?: ""
        val token = PendingSaves.put(SaveData(target, username, password))
        val intent = Intent(this, AutofillActivity::class.java)
            .putExtra(AutofillActivity.MODE, AutofillActivity.SAVE)
            .putExtra(AutofillActivity.TOKEN, token)
        val pending = PendingIntent.getActivity(
            this, token.hashCode(), intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_CANCEL_CURRENT,
        )
        callback.onSuccess(pending.intentSender)
    }

    private fun presentation() = RemoteViews(packageName, R.layout.autofill_item).apply {
        setTextViewText(R.id.text, getString(R.string.autofill_fill))
    }
}
