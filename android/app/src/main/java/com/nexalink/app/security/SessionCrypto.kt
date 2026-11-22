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
 * Ephemeral ECDH + HKDF-SHA256 + AES-256-GCM primitives.
 * Authentication MUST happen before trusting the derived keys.
 * Session IDs and direction are bound into HKDF context.
 */
object SessionCrypto {
    fun ephemeralKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()

    fun deriveKey(
        local: KeyPair,
        remotePublicKey: ByteArray,
        transcript: ByteArray,
        initiator: Boolean
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
                val label = if (initiator) "nexalink-v1-i2r" else "nexalink-v1-r2i"
                val info = label.toByteArray(Charsets.US_ASCII) + byteArrayOf(1)
                mac.init(SecretKeySpec(prk, "HmacSHA256"))
                mac.update(info)
                return SecretKeySpec(mac.doFinal().copyOf(32), "AES")
            } finally {
                prk.fill(0)
            }
        } finally {
            shared.fill(0)
        }
    }
}

/** One directional cipher. The caller must supply the authenticated session transcript as AAD. */
class SessionCipher(private val key: SecretKey, private val aad: ByteArray) {
    private val random = SecureRandom()
    private var nextSequence = 0L
    private val seen = mutableSetOf<Long>()

    @Synchronized
    fun encrypt(plaintext: ByteArray): ByteArray {
        require(plaintext.size <= 60_000)
        require(nextSequence < Long.MAX_VALUE)
        val sequence = nextSequence++
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
        require(frame.size in 36..60_036)
        val buffer = ByteBuffer.wrap(frame)
        val sequence = buffer.long
        require(sequence >= 0 && sequence !in seen) { "Replay detected" }
        val nonce = ByteArray(12).also(buffer::get)
        val ciphertext = ByteArray(buffer.remaining()).also(buffer::get)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad + ByteBuffer.allocate(8).putLong(sequence).array())
        val plaintext = cipher.doFinal(ciphertext)
        seen.add(sequence)
        return plaintext
    }
}
