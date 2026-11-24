package com.nexalink.app.security

import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * P-256 ECDH + HKDF-SHA256 + AES-256-GCM.
 * HKDF labels and frame layout match desktop/src/crypto.rs.
 */
object SessionCrypto {
    fun ephemeralKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()

    fun deriveKey(
        local: KeyPair,
        remotePublicKey: ByteArray,
        transcript: ByteArray,
        initiatorToResponder: Boolean
    ): SecretKey {
        require(transcript.isNotEmpty() && transcript.size <= 8192)
        val remote = KeyFactory.getInstance("EC")
            .generatePublic(X509EncodedKeySpec(remotePublicKey))
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(local.private)
        agreement.doPhase(remote, true)
        val shared = agreement.generateSecret()
        try {
            val mac = Mac.getInstance("HmacSHA256")
            val salt = java.security.MessageDigest.getInstance("SHA-256").digest(transcript)
            mac.init(SecretKeySpec(salt, "HmacSHA256"))
            val prk = mac.doFinal(shared)
            try {
                val label = if (initiatorToResponder) "nexalink-v1-i2r" else "nexalink-v1-r2i"
                mac.init(SecretKeySpec(prk, "HmacSHA256"))
                mac.update(label.toByteArray(Charsets.US_ASCII))
                return SecretKeySpec(mac.doFinal(byteArrayOf(1)).copyOf(32), "AES")
            } finally {
                prk.fill(0)
            }
        } finally {
            shared.fill(0)
        }
    }
}

/**
 * One directional cipher. TCP ordering is enforced with a single expected
 * sequence counter, avoiding the unbounded replay set used by the prototype.
 */
class SessionCipher(private val key: SecretKey, private val aad: ByteArray) {
    private val random = SecureRandom()
    private var nextOutboundSequence = 0L
    private var nextInboundSequence = 0L

    @Synchronized
    fun encrypt(plaintext: ByteArray): ByteArray {
        require(plaintext.size <= MAX_PLAINTEXT_BYTES)
        require(nextOutboundSequence < Long.MAX_VALUE) { "Outbound sequence exhausted" }
        val sequence = nextOutboundSequence++
        val nonce = ByteArray(12).also(random::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad + ByteBuffer.allocate(8).putLong(sequence).array())
        val ciphertext = cipher.doFinal(plaintext)
        return ByteBuffer.allocate(8 + nonce.size + ciphertext.size)
            .putLong(sequence).put(nonce).put(ciphertext).array()
    }

    @Synchronized
    fun decrypt(frame: ByteArray): ByteArray {
        require(frame.size in MIN_FRAME_BYTES..MAX_FRAME_BYTES) { "Invalid encrypted frame length" }
        val buffer = ByteBuffer.wrap(frame)
        val sequence = buffer.long
        require(sequence == nextInboundSequence && sequence < Long.MAX_VALUE) {
            "Out-of-order or replayed sequence"
        }
        val nonce = ByteArray(12).also(buffer::get)
        val ciphertext = ByteArray(buffer.remaining()).also(buffer::get)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad + ByteBuffer.allocate(8).putLong(sequence).array())
        val plaintext = cipher.doFinal(ciphertext)
        nextInboundSequence++
        return plaintext
    }

    companion object {
        const val MAX_PLAINTEXT_BYTES = 48_000
        private const val MIN_FRAME_BYTES = 36
        private const val MAX_FRAME_BYTES = MAX_PLAINTEXT_BYTES + 36
    }
}
