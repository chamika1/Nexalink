package com.nexalink.app.security

import java.security.SecureRandom
import java.util.Base64

/**
 * Ephemeral challenge data for a future mutually authenticated transport.
 * Both parties must bind the challenges to their identities and session.
 */
data class PairingChallenge(
    val nonce: String,
    val createdAtMillis: Long,
    val expiresAtMillis: Long
) {
    fun isValid(nowMillis: Long): Boolean =
        nowMillis >= createdAtMillis && nowMillis < expiresAtMillis

    companion object {
        fun create(nowMillis: Long = System.currentTimeMillis()): PairingChallenge {
            val bytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
            return PairingChallenge(
                Base64.getUrlEncoder().withoutPadding().encodeToString(bytes),
                nowMillis, nowMillis + 120_000L
            )
        }
    }
}
