package com.nexalink.app.security

import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Transcript signature primitives for mutually authenticated pairing.
 * Trust requires verifying BOTH signatures, an out-of-band code and
 * explicit approval. This class alone does not establish a session.
 */
class SessionAuthenticator {
    fun sign(transcript: SessionTranscript): String {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = requireNotNull(store.getKey("nexalink-device-identity-v1", null)) as PrivateKey
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(key)
        signer.update(transcript.bytes())
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign())
    }

    fun verify(transcript: SessionTranscript, initiator: Boolean, signature: String): Boolean {
        return runCatching {
            val encoded = if (initiator) transcript.initiatorPublicKey else transcript.responderPublicKey
            val key = KeyFactory.getInstance("EC").generatePublic(
                X509EncodedKeySpec(Base64.getUrlDecoder().decode(encoded))
            )
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(key)
            verifier.update(transcript.bytes())
            verifier.verify(Base64.getUrlDecoder().decode(signature))
        }.getOrDefault(false)
    }
}
