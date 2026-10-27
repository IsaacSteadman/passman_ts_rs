package com.firaxite.passman.autofill

import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Bundle
import android.service.autofill.Dataset
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import com.firaxite.passman.PageHost
import com.firaxite.passman.R
import com.firaxite.passman.Reply
import org.json.JSONArray
import org.json.JSONObject
import kotlin.concurrent.thread

/**
 * The autofill screen (android/web/autofill.html): unlocks an account and
 * returns the login the user picked to Android, which fills it in; or saves
 * what was typed. Shown over the app being filled, and not in recent apps.
 */
class AutofillActivity : PageHost() {
    override val page = "autofill.html"

    private var form: ParsedForm? = null
    private var target: Target? = null
    private var save: SaveData? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setResult(RESULT_CANCELED)
        when (intent.getStringExtra(MODE)) {
            FILL -> {
                @Suppress("DEPRECATION")
                val structure = intent.getParcelableExtra<AssistStructure>(AutofillManager.EXTRA_ASSIST_STRUCTURE)
                form = structure?.let(StructureParser::parse)
                target = form?.let { AppIdentity.target(this, it) }
            }
            SAVE -> {
                save = intent.getStringExtra(TOKEN)?.let(PendingSaves::get)
                target = save?.target
            }
        }
        if (target == null) {
            finish()
            return
        }
        showPage()
    }

    override fun handle(method: String, params: JSONObject, reply: Reply): Boolean {
        when (method) {
            "autofillContext" -> reply.ok(
                JSONObject()
                    .put("mode", if (save != null) "save" else "fill")
                    .put("target", target!!.toJson())
                    .put(
                        "fields",
                        JSONObject()
                            .put("username", form?.username != null)
                            .put("password", form?.passwords?.isNotEmpty() == true)
                            .put("otp", form?.otp != null),
                    )
                    .put(
                        "save",
                        save?.let { JSONObject().put("username", it.username).put("password", it.password) }
                            ?: JSONObject.NULL,
                    ),
            )

            "autofillFill" -> {
                val dataset = dataset(
                    params.getString("username"),
                    params.getString("password"),
                    params.getString("otp"),
                )
                if (dataset == null) {
                    reply.error("There's nothing in this login to fill into this form.")
                } else {
                    setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset))
                    reply.ok()
                    finish()
                }
            }

            "autofillDone" -> {
                reply.ok()
                finish()
            }

            "checkAppLinks" -> {
                val app = target as? Target.App ?: return false
                val urls = params.getJSONArray("urls").let { list -> (0 until list.length()).map(list::getString) }
                thread {
                    try {
                        reply.ok(JSONObject().put("verified", JSONArray(AssetLinks.verifiedOrigins(urls, app))))
                    } catch (e: Exception) {
                        reply.fail(e)
                    }
                }
            }

            else -> return false
        }
        return true
    }

    private fun dataset(username: String, password: String, otp: String): Dataset? {
        val form = form ?: return null
        val presentation = RemoteViews(packageName, R.layout.autofill_item).apply {
            setTextViewText(R.id.text, getString(R.string.autofill_fill))
        }
        val builder = Dataset.Builder()
        var any = false
        fun set(id: AutofillId, value: String) {
            if (value.isEmpty()) return
            @Suppress("DEPRECATION")
            builder.setValue(id, AutofillValue.forText(value), presentation)
            any = true
        }
        form.username?.let { set(it.id, username) }
        form.passwords.forEach { set(it.id, password) }
        form.otp?.let { set(it.id, otp) }
        return if (any) builder.build() else null
    }

    override fun onDestroy() {
        if (isFinishing) intent.getStringExtra(TOKEN)?.let(PendingSaves::remove)
        super.onDestroy()
    }

    companion object {
        const val MODE = "mode"
        const val FILL = "fill"
        const val SAVE = "save"
        const val TOKEN = "token"
    }
}
