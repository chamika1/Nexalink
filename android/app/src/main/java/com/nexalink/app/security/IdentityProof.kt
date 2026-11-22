package com.nexalink.app.security

import java.security.KeyFactory
import java.security.KeyStore
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/** A nonce-based signature primitive, not a complete authenticated handshake. */
class IdentityProof {
    private val random = SecureRandom()

    fun newChallenge(): ByteArray = ByteArray(32).also(random::nextBytes)

    fun signChallenge(challenge: ByteArray): String {
        require(challenge.size == 32)
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = requireNotNull(store.getKey("nexalink-device-identity-v1", null))
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(key as java.security.PrivateKey)
        signer.update(domainSeparated(challenge))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign())
    }

    fun verifyChallenge(encodedPublicKey: String, challenge: ByteArray, proof: String): Boolean {
        if (challenge.size != 32) return false
        return try {
            val bytes = Base64.getUrlDecoder().decode(encodedPublicKey)
            val publicKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(bytes))
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(publicKey)
            verifier.update(domainSeparated(challenge))
            verifier.verify(Base64.getUrlDecoder().decode(proof))
        } catch (_: Exception) {
            false
        }
    }

    private fun domainSeparated(challenge: ByteArray) =
        "NexaLink identity proof v1\u0000".toByteArray(Charsets.UTF_8) + challenge
}
