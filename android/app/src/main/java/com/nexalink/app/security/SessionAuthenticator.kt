package com.nexalink.app.security

import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Transcript signature primitives. The remote key must be pinned separately;
 * a valid signature from an untrusted key never establishes trust.
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
            val identity = if (initiator) transcript.initiatorIdentitySpki
                else transcript.responderIdentitySpki
            verifySignature(identity, transcript.bytes(), Base64.getUrlDecoder().decode(signature))
        }.getOrDefault(false)
    }

    companion object {
        fun verifySignature(
            identitySpki: ByteArray,
            transcriptBytes: ByteArray,
            signatureDer: ByteArray
        ): Boolean {
            if (identitySpki.isEmpty() || identitySpki.size > 2048 ||
                transcriptBytes.isEmpty() || transcriptBytes.size > 8192 ||
                signatureDer.isEmpty() || signatureDer.size > 256) return false
            return try {
                val key = KeyFactory.getInstance("EC")
                    .generatePublic(X509EncodedKeySpec(identitySpki))
                val verifier = Signature.getInstance("SHA256withECDSA")
                verifier.initVerify(key)
                verifier.update(transcriptBytes)
                verifier.verify(signatureDer)
            } catch (_: Exception) {
                false
            }
        }
    }
}
