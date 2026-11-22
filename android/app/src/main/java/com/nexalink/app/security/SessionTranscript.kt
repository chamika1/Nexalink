package com.nexalink.app.security

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.util.Base64

/** Canonical, role-bound pairing transcript. Not a network transport. */
data class SessionTranscript(
    val sessionId: String,
    val initiatorPublicKey: String,
    val responderPublicKey: String,
    val initiatorNonce: String,
    val responderNonce: String
) {
    fun bytes(): ByteArray {
        require(sessionId.length in 16..128)
        val initiatorKey = decode(initiatorPublicKey, 64, 512)
        val responderKey = decode(responderPublicKey, 64, 512)
        val firstNonce = decode(initiatorNonce, 32, 32)
        val secondNonce = decode(responderNonce, 32, 32)
        require(!initiatorKey.contentEquals(responderKey)) { "Peer identities must differ" }
        require(!firstNonce.contentEquals(secondNonce)) { "Nonces must differ" }
        val stream = ByteArrayOutputStream()
        DataOutputStream(stream).use { out ->
            out.writeUTF("NexaLink pairing transcript v1")
            out.writeUTF(sessionId)
            for (part in listOf(initiatorKey, responderKey, firstNonce, secondNonce)) {
                out.writeInt(part.size)
                out.write(part)
            }
        }
        return stream.toByteArray()
    }

    fun verificationCode(): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes())
        val number = ((digest[0].toInt() and 255) shl 16) or
            ((digest[1].toInt() and 255) shl 8) or (digest[2].toInt() and 255)
        return (number % 1_000_000).toString().padStart(6, '0')
    }

    private fun decode(value: String, min: Int, max: Int): ByteArray {
        require(value.length <= 1000)
        val bytes = Base64.getUrlDecoder().decode(value)
        require(bytes.size in min..max)
        return bytes
    }
}
