package com.nexalink.app.security

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest

/**
 * Canonical NexaLink v1 transcript shared with the Windows Rust implementation.
 * Field order and big-endian length prefixes are protocol-critical.
 */
data class SessionTranscript(
    val initiatorIdentitySpki: ByteArray,
    val responderIdentitySpki: ByteArray,
    val initiatorEphemeralSpki: ByteArray,
    val responderEphemeralSpki: ByteArray,
    val initiatorNonce: ByteArray,
    val responderNonce: ByteArray
) {
    fun bytes(): ByteArray {
        val keys = listOf(
            initiatorIdentitySpki, responderIdentitySpki,
            initiatorEphemeralSpki, responderEphemeralSpki
        )
        require(keys.all { it.isNotEmpty() && it.size <= MAX_KEY_BYTES }) {
            "Invalid transcript public key length"
        }
        require(!initiatorIdentitySpki.contentEquals(responderIdentitySpki)) {
            "Peer identities must differ"
        }
        require(!initiatorEphemeralSpki.contentEquals(responderEphemeralSpki)) {
            "Ephemeral keys must differ"
        }
        require(initiatorNonce.size == NONCE_BYTES && responderNonce.size == NONCE_BYTES) {
            "Invalid transcript nonce length"
        }
        require(!initiatorNonce.contentEquals(responderNonce)) { "Nonces must differ" }

        val output = ByteArrayOutputStream()
        output.write(DOMAIN)
        DataOutputStream(output).use { data ->
            listOf(
                initiatorIdentitySpki, responderIdentitySpki,
                initiatorEphemeralSpki, responderEphemeralSpki,
                initiatorNonce, responderNonce
            ).forEach { field ->
                data.writeInt(field.size)
                data.write(field)
            }
        }
        return output.toByteArray().also {
            require(it.size <= MAX_TRANSCRIPT_BYTES) { "Transcript too long" }
        }
    }

    fun verificationCode(): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes())
        val number = ((digest[0].toInt() and 255) shl 16) or
            ((digest[1].toInt() and 255) shl 8) or (digest[2].toInt() and 255)
        return (number % 1_000_000).toString().padStart(6, '0')
    }

    companion object {
        private const val MAX_KEY_BYTES = 2048
        private const val NONCE_BYTES = 32
        private const val MAX_TRANSCRIPT_BYTES = 8192
        private val DOMAIN = "nexalink-authenticated-session-v1\u0000"
            .toByteArray(Charsets.US_ASCII)
    }
}
