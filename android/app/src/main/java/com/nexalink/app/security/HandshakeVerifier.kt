package com.nexalink.app.security

import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Verifies an authenticated handshake against a previously trusted identity key.
 * Trust/pinning must be established by an explicit, user-confirmed pairing flow.
 * This does not grant consent or enable a network listener.
 */
object HandshakeVerifier {
    fun verify(
        pinnedIdentitySpki: ByteArray,
        presentedIdentitySpki: ByteArray,
        transcript: ByteArray,
        signatureDer: ByteArray
    ): Boolean {
        require(pinnedIdentitySpki.isNotEmpty() && pinnedIdentitySpki.size <= 2048)
        require(presentedIdentitySpki.isNotEmpty() && presentedIdentitySpki.size <= 2048)
        require(transcript.size in 1..8192)
        require(signatureDer.size in 1..256)
        if (!MessageDigest.isEqual(pinnedIdentitySpki, presentedIdentitySpki)) return false
        return try {
            val identity = KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(presentedIdentitySpki))
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(identity)
            verifier.update(transcript)
            verifier.verify(signatureDer)
        } catch (_: java.security.GeneralSecurityException) {
            false
        }
    }
}
