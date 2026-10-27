package com.firaxite.passman.autofill

import android.app.assist.AssistStructure
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId

/** The login fields of a form, and what's typed in them. */
class ParsedForm(
    val packageName: String?,
    val webDomain: String?,
    val webScheme: String?,
    val username: Field?,
    val passwords: List<Field>,
    val newPasswords: List<Field>,
    val otp: Field?,
) {
    class Field(val id: AutofillId, val value: String?)

    val isEmpty get() = username == null && passwords.isEmpty() && newPasswords.isEmpty() && otp == null

    /** The fields Passman fills. */
    val fillIds: List<AutofillId>
        get() = listOfNotNull(username?.id, otp?.id) + passwords.map { it.id }

    /** The fields whose values are saved. */
    val saveIds: List<AutofillId>
        get() = listOfNotNull(username?.id) + (newPasswords.ifEmpty { passwords }).map { it.id }
}

/** Finds the login fields in a screen's structure, from autofill hints,
 *  HTML attributes (in browsers), input types and, failing those, names. */
object StructureParser {
    private enum class Kind { USERNAME, PASSWORD, NEW_PASSWORD, OTP, TEXT }

    private class Node(val node: AssistStructure.ViewNode, val kind: Kind)

    fun parse(structure: AssistStructure): ParsedForm {
        val nodes = mutableListOf<Node>()
        var webDomain: String? = null
        var webScheme: String? = null
        fun visit(node: AssistStructure.ViewNode) {
            if (webDomain == null && !node.webDomain.isNullOrEmpty()) {
                webDomain = node.webDomain
                webScheme = node.webScheme
            }
            if (node.autofillId != null && node.autofillType == View.AUTOFILL_TYPE_TEXT &&
                node.visibility == View.VISIBLE
            ) {
                kindOf(node)?.let { nodes.add(Node(node, it)) }
            }
            for (i in 0 until node.childCount) visit(node.getChildAt(i))
        }
        for (i in 0 until structure.windowNodeCount) visit(structure.getWindowNodeAt(i).rootViewNode)

        fun field(n: Node) = ParsedForm.Field(n.node.autofillId!!, n.node.autofillValue?.takeIf { it.isText }?.textValue?.toString())
        val passwords = nodes.filter { it.kind == Kind.PASSWORD }
        val newPasswords = nodes.filter { it.kind == Kind.NEW_PASSWORD }
        val firstPassword = nodes.indexOfFirst { it.kind == Kind.PASSWORD || it.kind == Kind.NEW_PASSWORD }
        // without a username field, the text field just before the password
        val username = nodes.firstOrNull { it.kind == Kind.USERNAME }
            ?: nodes.take(maxOf(firstPassword, 0)).lastOrNull { it.kind == Kind.TEXT }
        return ParsedForm(
            packageName = structure.activityComponent?.packageName,
            webDomain = webDomain,
            webScheme = webScheme,
            username = username?.let(::field),
            passwords = passwords.map(::field),
            newPasswords = newPasswords.map(::field),
            otp = nodes.firstOrNull { it.kind == Kind.OTP }?.let(::field),
        )
    }

    private fun kindOf(node: AssistStructure.ViewNode): Kind? {
        for (hint in node.autofillHints.orEmpty()) {
            when (hint.lowercase().replace(Regex("[^a-z]"), "")) {
                "username", "emailaddress", "email", "newusername" -> return Kind.USERNAME
                "password", "currentpassword" -> return Kind.PASSWORD
                "newpassword" -> return Kind.NEW_PASSWORD
                "smsotpcode", "onetimecode", "otp", "faappotpcode", "smsotp" -> return Kind.OTP
            }
        }
        val html = node.htmlInfo
        if (html != null) {
            if (!html.tag.equals("input", true)) return null
            val attributes = html.attributes.orEmpty()
                .associate { (it.first ?: "").lowercase() to (it.second ?: "").lowercase() }
            val autocomplete = attributes["autocomplete"].orEmpty()
            val type = attributes["type"].orEmpty()
            when {
                "one-time-code" in autocomplete -> return Kind.OTP
                "new-password" in autocomplete -> return Kind.NEW_PASSWORD
                type == "password" || "current-password" in autocomplete -> return Kind.PASSWORD
                type == "email" || "username" in autocomplete || "email" in autocomplete -> return Kind.USERNAME
                type == "hidden" || type == "submit" || type == "button" || type == "checkbox" ||
                    type == "radio" || type == "search" -> return null
            }
        }
        val inputType = node.inputType
        val variation = inputType and InputType.TYPE_MASK_VARIATION
        val klass = inputType and InputType.TYPE_MASK_CLASS
        val words = listOfNotNull(node.idEntry, node.hint, html?.attributes?.firstOrNull { it.first == "name" }?.second ?: "")
            .joinToString(" ").lowercase()
        if (klass == InputType.TYPE_CLASS_TEXT && (
                variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
                    variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD ||
                    variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                ) || klass == InputType.TYPE_CLASS_NUMBER && variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD
        ) return if (Regex("new|confirm|repeat").containsMatchIn(words)) Kind.NEW_PASSWORD else Kind.PASSWORD
        if (klass == InputType.TYPE_CLASS_TEXT && (
                variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
                    variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS
                )
        ) return Kind.USERNAME
        if (Regex("otp|totp|2fa|one.?time|verification.?code|auth.?code").containsMatchIn(words)) return Kind.OTP
        if (Regex("user|e.?mail|login|account").containsMatchIn(words)) return Kind.USERNAME
        if (Regex("pass").containsMatchIn(words)) return Kind.PASSWORD
        return if (klass == InputType.TYPE_CLASS_TEXT || klass == 0) Kind.TEXT else null
    }
}
