package com.firaxite.passman

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Why a biometric unlock call failed; `kind` as in the pages' NativeError. */
class UnlockKeyException(message: String, val kind: String) : Exception(message)

/**
 * Biometric unlock's keys: one AES-256-GCM key per account in the Android
 * Keystore, in StrongBox where the device has it (else the TEE). A key can't
 * be read out of the Keystore, is used only right after a strong biometric
 * check (each time), only while the device is unlocked, and is deleted by
 * Android when biometrics are added or removed. It encrypts the keys the
 * account's password would derive.
 */
object UnlockKeys {
    private const val PREFIX = "passman-unlock-"
    private const val KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"

    fun available(context: Context): Boolean =
        context.getSystemService(BiometricManager::class.java)
            .canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    private fun keyStore() = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private fun createKey(context: Context, alias: String): SecretKey {
        val strongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        fun generate(inStrongBox: Boolean): SecretKey {
            val spec = KeyGenParameterSpec.Builder(
                PREFIX + alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true)
                .setUnlockedDeviceRequired(true)
                .setIsStrongBoxBacked(inStrongBox)
                .build()
            return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
                .apply { init(spec) }
                .generateKey()
        }
        return if (strongBox) {
            try {
                generate(true)
            } catch (_: StrongBoxUnavailableException) {
                generate(false)
            }
        } else generate(false)
    }

    private fun existingKey(alias: String): SecretKey? =
        keyStore().getKey(PREFIX + alias, null) as SecretKey?

    /** A cipher to encrypt with the account's key, created if needed (again,
     *  if Android invalidated it). */
    fun encryptCipher(context: Context, alias: String): Cipher {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        try {
            cipher.init(Cipher.ENCRYPT_MODE, existingKey(alias) ?: createKey(context, alias))
        } catch (_: KeyPermanentlyInvalidatedException) {
            delete(alias)
            cipher.init(Cipher.ENCRYPT_MODE, createKey(context, alias))
        }
        return cipher
    }

    fun decryptCipher(alias: String, iv: ByteArray): Cipher {
        val key = existingKey(alias)
            ?: throw UnlockKeyException("The key for biometric unlock is gone.", "invalidated")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        } catch (_: KeyPermanentlyInvalidatedException) {
            delete(alias)
            throw UnlockKeyException("Biometrics changed on this device.", "invalidated")
        }
        return cipher
    }

    fun delete(alias: String) {
        keyStore().deleteEntry(PREFIX + alias)
    }

    /** Deletes every account's key (when the server is changed). */
    fun deleteAll() {
        val store = keyStore()
        for (alias in store.aliases().toList()) if (alias.startsWith(PREFIX)) store.deleteEntry(alias)
    }

    /** Shows the biometric prompt, which unlocks `cipher` for one use. */
    fun authenticate(
        activity: Activity,
        title: String,
        cipher: Cipher,
        done: (Result<Cipher>) -> Unit,
    ) {
        val executor = activity.mainExecutor
        var finished = false
        val finish = { result: Result<Cipher> ->
            if (!finished) {
                finished = true
                done(result)
            }
        }
        val prompt = BiometricPrompt.Builder(activity)
            .setTitle(title)
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            .setConfirmationRequired(false)
            .setNegativeButton("Use password", executor) { _, _ ->
                finish(Result.failure(UnlockKeyException("cancelled", "cancelled")))
            }
            .build()
        prompt.authenticate(
            BiometricPrompt.CryptoObject(cipher),
            CancellationSignal(),
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val unlocked = result.cryptoObject?.cipher
                    finish(
                        if (unlocked != null) Result.success(unlocked)
                        else Result.failure(UnlockKeyException("No key was unlocked.", "error")),
                    )
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    val cancelled = errorCode == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED ||
                        errorCode == BiometricPrompt.BIOMETRIC_ERROR_CANCELED ||
                        errorCode == BiometricPrompt.BIOMETRIC_ERROR_TIMEOUT
                    finish(Result.failure(UnlockKeyException(errString.toString(), if (cancelled) "cancelled" else "error")))
                }
            },
        )
    }
}
