package com.firaxite.passman

import android.util.Base64
import java.security.MessageDigest

/** base64url without padding, as the web app's toBase64Url / fromBase64Url. */
fun ByteArray.toBase64Url(): String =
    Base64.encodeToString(this, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

fun String.fromBase64Url(): ByteArray =
    Base64.decode(this, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

fun ByteArray.sha256(): ByteArray = MessageDigest.getInstance("SHA-256").digest(this)

/** "AB:CD:…", the way certificate fingerprints are usually written. */
fun ByteArray.toColonHex(): String = joinToString(":") { "%02X".format(it) }
