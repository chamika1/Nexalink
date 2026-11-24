package com.nexalink.app.security

import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Versioned pairing invitation format.
 * Invitations carry only a public key and a user-visible device label.
 * They do not grant access; both devices must approve and verify identities.
 */
data class PairingInvitation(
    val version: Int,
    val deviceName: String,
    val encodedPublicKey: String
) {
    fun serialize(): String {
        require(version == 1)
        val nameBytes = deviceName.toByteArray(Charsets.UTF_8)
        require(nameBytes.size <= 64 && deviceName.isNotBlank() && deviceName.none(Char::isISOControl))
        validatePublicKey(encodedPublicKey)
        val name = Base64.getUrlEncoder().withoutPadding().encodeToString(nameBytes)
        return "nexalink:pair:1:$name:$encodedPublicKey"
    }

    fun fingerprint(): String {
        val key = Base64.getUrlDecoder().decode(encodedPublicKey)
        return MessageDigest.getInstance("SHA-256").digest(key)
            .joinToString(":") { "%02X".format(it.toInt() and 255) }
    }

    companion object {
        private val p256 by lazy {
            AlgorithmParameters.getInstance("EC").apply {
                init(ECGenParameterSpec("secp256r1"))
            }.getParameterSpec(ECParameterSpec::class.java)
        }

        private fun validatePublicKey(encoded: String) {
            require(encoded.length <= 684) { "Invalid public key" }
            val bytes = Base64.getUrlDecoder().decode(encoded)
            val key = runCatching {
                KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(bytes)) as ECPublicKey
            }.getOrElse { throw IllegalArgumentException("Invalid public key", it) }
            val params = key.params
            require(params.curve == p256.curve && params.generator == p256.generator &&
                params.order == p256.order && params.cofactor == p256.cofactor &&
                bytes.contentEquals(key.encoded)) { "Expected a P-256 public key" }
        }

        fun parse(raw: String): PairingInvitation {
            require(raw.length <= 6000) { "Invitation too long" }
            val parts = raw.split(':')
            require(parts.size == 5 && parts[0] == "nexalink" &&
                parts[1] == "pair" && parts[2] == "1") { "Unsupported invitation" }
            val nameBytes = Base64.getUrlDecoder().decode(parts[3])
            require(nameBytes.size in 1..64) { "Invalid device name" }
            val name = nameBytes.toString(Charsets.UTF_8)
            require(name.toByteArray(Charsets.UTF_8).contentEquals(nameBytes) &&
                name.isNotBlank() && name.none(Char::isISOControl)) { "Invalid device name" }
            validatePublicKey(parts[4])
            return PairingInvitation(1, name, parts[4])
        }
    }
}
