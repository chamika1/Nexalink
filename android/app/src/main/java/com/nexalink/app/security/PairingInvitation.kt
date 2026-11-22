package com.nexalink.app.security

import java.security.MessageDigest
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
        require(deviceName.isNotBlank() && deviceName.length <= 64)
        require(encodedPublicKey.length <= 4096)
        val name = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(deviceName.toByteArray(Charsets.UTF_8))
        return "nexalink:pair:1:$name:$encodedPublicKey"
    }

    fun fingerprint(): String {
        val key = Base64.getUrlDecoder().decode(encodedPublicKey)
        return MessageDigest.getInstance("SHA-256").digest(key)
            .joinToString(":") { "%02X".format(it.toInt() and 255) }
    }

    companion object {
        fun parse(raw: String): PairingInvitation {
            require(raw.length <= 6000) { "Invitation too long" }
            val parts = raw.split(':')
            require(parts.size == 5 && parts[0] == "nexalink" &&
                parts[1] == "pair" && parts[2] == "1") { "Unsupported invitation" }
            val nameBytes = Base64.getUrlDecoder().decode(parts[3])
            require(nameBytes.size in 1..64) { "Invalid device name" }
            val name = nameBytes.toString(Charsets.UTF_8)
            require(name.isNotBlank()) { "Invalid device name" }
            val keyBytes = Base64.getUrlDecoder().decode(parts[4])
            require(keyBytes.size in 64..512) { "Invalid public key" }
            return PairingInvitation(1, name, parts[4])
        }
    }
}
