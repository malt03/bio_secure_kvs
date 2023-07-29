package com.example.bio_secure_kvs

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties.*
import android.util.Base64
import android.util.Log
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import java.security.KeyStore
import java.util.concurrent.Executor
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import kotlinx.coroutines.flow.first

val Context.vioSecureKVS: DataStore<Preferences> by preferencesDataStore(name = "com.malt.vio_secure_kvs")

class KeyChainAccessor {
  sealed class Operation {}
  class Get(val encrypted: ByteArray, val callback: (ByteArray?) -> Unit): Operation()
  class Set(val context: Context, val key: String, val plain: ByteArray, val callback: () -> Unit): Operation()

  companion object {
    private var operation: Operation? = null

    private var executor: Executor? = null
    private var biometricPrompt: BiometricPrompt? = null

    fun get(context: Context, activity: FragmentActivity, service: String, key: String, callback: (ByteArray?) -> Unit) {
      GlobalScope.launch {
        val saved = context.vioSecureKVS.data.map { it[stringPreferencesKey("$key.$service")] }.first()
        
        val encrypted = Base64.decode(saved, Base64.DEFAULT)
        val ivEnd = encrypted[0].toUInt().toInt() + 1
        val iv = encrypted.sliceArray(1 until ivEnd)
        operation = Get(encrypted.sliceArray(ivEnd until encrypted.size), callback)

        val cipher = getCipher()
        val secretKey = getOrGenerateKey(service)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))

        val biometricPrompt = getBiometricPrompt(context, activity)
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
          .setTitle("Biometric login for my app")
          .setSubtitle("Log in using your biometric credential")
          .setNegativeButtonText("Use account password")
          .build()

        activity.runOnUiThread {
          biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        }
      }
    }

    fun set(context: Context, activity: FragmentActivity, service: String, key: String, value: ByteArray, callback: () -> Unit) {
      operation = Set(context, "$key.$service", value, callback)

      val cipher = getCipher()
      val secretKey = getOrGenerateKey(service)
      cipher.init(Cipher.ENCRYPT_MODE, secretKey)
      
      val biometricPrompt = getBiometricPrompt(context, activity)
      val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Biometric login for my app")
        .setSubtitle("Log in using your biometric credential")
        .setNegativeButtonText("Use account password")
        .build()
      biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    }

    fun delete(context: Context, service: String, key: String): Boolean {
      return false
    }

    private fun getExecutor(context: Context): Executor {
      val tmp = executor
      if (tmp != null) { return tmp }
      
      val created = ContextCompat.getMainExecutor(context)
      executor = created
      return created
    }

    private fun getBiometricPrompt(context: Context, activity: FragmentActivity): BiometricPrompt {
      val tmp = biometricPrompt
      if (tmp != null) { return tmp }

      val callback = object: BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationError(
          errorCode: Int,
          errString: CharSequence
        ) {
          super.onAuthenticationError(errorCode, errString)
        }

        override fun onAuthenticationFailed() {
          super.onAuthenticationFailed()
        }

        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
          super.onAuthenticationSucceeded(result)

          val o = operation ?: return
          val cipher = result.cryptoObject!!.cipher!!

          when (o) {
            is Get -> {
              o.callback(cipher.doFinal(o.encrypted))
            }
            is Set -> {
              val iv = cipher.iv
              val ivSize = byteArrayOf(iv.size.toUInt().toByte())
              val encrypted = ivSize + iv + cipher.doFinal(o.plain)
              GlobalScope.launch {
                o.context.vioSecureKVS.edit {
                  it[stringPreferencesKey(o.key)] = Base64.encodeToString(encrypted, Base64.DEFAULT)
                }
                o.callback()
              }
            }
          }
        }
      }

      return BiometricPrompt(activity, getExecutor(context), callback)
    }

    private fun generateSecretKey(keyName: String): SecretKey {
      val builder = KeyGenParameterSpec.Builder(
        keyName,
        PURPOSE_ENCRYPT or PURPOSE_DECRYPT
      )
      val spec = builder
        .setBlockModes(BLOCK_MODE_CBC)
        .setEncryptionPaddings(ENCRYPTION_PADDING_PKCS7)
        .setUserAuthenticationRequired(true)
        .setUserAuthenticationParameters(
          0,
          AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL
        )
        .build()
      val keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM_AES, "AndroidKeyStore")
      keyGenerator.init(spec)
      
      return keyGenerator.generateKey()
    }

    private fun getOrGenerateKey(keyName: String): SecretKey {
      val keyStore = KeyStore.getInstance("AndroidKeyStore")
      keyStore.load(null)

      return if (keyStore.containsAlias(keyName)) {
        keyStore.getKey(keyName, null) as SecretKey
      } else {
        generateSecretKey(keyName)
      }
    }
    
    private fun getCipher(): Cipher {
      return Cipher.getInstance(KEY_ALGORITHM_AES + "/"
        + BLOCK_MODE_CBC + "/"
        + ENCRYPTION_PADDING_PKCS7)
    }
  }
}
