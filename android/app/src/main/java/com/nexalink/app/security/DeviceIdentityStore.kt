package com.nexalink.app.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec

/**
 * Local device identity prototype.
 * P-256 signing keys are generated in Android Keystore; the private key
 * is not exported. This is NOT a complete pairing or E2EE protocol.
 */
class DeviceIdentityStore {
    private val alias = "nexalink-device-identity-v1"
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    @Synchronized
    fun publicKey(): PublicKey {
        if (!keyStore.containsAlias(alias)) {
            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
            )
            val spec = KeyGenParameterSpec.Builder(
                alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            ).setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
            generator.initialize(spec)
            generator.generateKeyPair()
        }
        return requireNotNull(keyStore.getCertificate(alias)) {
            "Device identity certificate unavailable"
        }.publicKey
    }

    fun fingerprint(): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(publicKey().encoded)
        return digest.joinToString(":") { "%02X".format(it.toInt() and 0xff) }
    }
}
