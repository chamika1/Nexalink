package com.nexalink.app.security

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/** A one-use challenge for a manually verified pair of device identities. */
internal class ManualPairing(
    private val localFingerprint: String,
    private val peer: PairingInvitation,
    private val clock: () -> Long,
    private val proof: IdentityProof = IdentityProof()
) {
    private val peerFingerprint = peer.fingerprint()
    private var pending: String? = null
    private var expiresAt = 0L

    init {
        require(localFingerprint != peerFingerprint) { "Choose an invitation from another device" }
    }

    fun createChallenge(): String {
        val nonce = ByteArray(32).also(SecureRandom()::nextBytes)
        return encoder.encodeToString(nonce).also {
            pending = it
            expiresAt = clock() + 120_000
        }
    }

    fun respond(challenge: String): String =
        proof.signChallenge(boundChallenge(challenge, peerFingerprint, localFingerprint))

    fun verify(response: String): Boolean {
        val challenge = pending ?: return false
        if (clock() >= expiresAt || response.length > 350) return false
        val valid = proof.verifyChallenge(
            peer.encodedPublicKey,
            boundChallenge(challenge, localFingerprint, peerFingerprint),
            response
        )
        if (valid) pending = null
        return valid
    }

    companion object {
        private val encoder = Base64.getUrlEncoder().withoutPadding()

        internal fun boundChallenge(challenge: String, verifier: String, signer: String): ByteArray {
            require(challenge.length == 43) { "Invalid pairing challenge" }
            val nonce = Base64.getUrlDecoder().decode(challenge)
            require(nonce.size == 32 && encoder.encodeToString(nonce) == challenge) {
                "Invalid pairing challenge"
            }
            val context = "NexaLink manual pairing v1\u0000$verifier\u0000$signer\u0000"
            return MessageDigest.getInstance("SHA-256").digest(context.toByteArray(Charsets.UTF_8) + nonce)
        }
    }
}
