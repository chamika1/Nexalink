package com.nexalink.app.security

import java.security.KeyPair
import java.security.MessageDigest

/**
 * Builds encryption ciphers only after both signatures, both pinned identities,
 * both ephemeral keys and the out-of-band comparison code have been verified.
 * This class does not grant consent or open a network connection.
 */
data class AuthenticatedSessionMaterial(
    val sessionId: String,
    val peerId: String,
    val verificationCode: String,
    val outboundCipher: SessionCipher,
    val inboundCipher: SessionCipher
)

object AuthenticatedSessionFactory {
    fun establish(
        sessionId: String,
        peerId: String,
        transcript: SessionTranscript,
        localIdentitySpki: ByteArray,
        pinnedRemoteIdentitySpki: ByteArray,
        localEphemeral: KeyPair,
        remoteEphemeralSpki: ByteArray,
        localSignatureDer: ByteArray,
        remoteSignatureDer: ByteArray,
        localIsInitiator: Boolean,
        confirmedVerificationCode: String
    ): AuthenticatedSessionMaterial {
        require(sessionId.length in 8..128) { "Invalid session id" }
        require(peerId == fingerprint(pinnedRemoteIdentitySpki)) {
            "Peer id does not match the trusted identity pin"
        }

        val expectedLocalIdentity = if (localIsInitiator)
            transcript.initiatorIdentitySpki else transcript.responderIdentitySpki
        val expectedRemoteIdentity = if (localIsInitiator)
            transcript.responderIdentitySpki else transcript.initiatorIdentitySpki
        require(MessageDigest.isEqual(localIdentitySpki, expectedLocalIdentity)) {
            "Local identity does not match transcript role"
        }
        require(MessageDigest.isEqual(pinnedRemoteIdentitySpki, expectedRemoteIdentity)) {
            "Remote identity does not match trusted pin"
        }

        val expectedLocalEphemeral = if (localIsInitiator)
            transcript.initiatorEphemeralSpki else transcript.responderEphemeralSpki
        val expectedRemoteEphemeral = if (localIsInitiator)
            transcript.responderEphemeralSpki else transcript.initiatorEphemeralSpki
        require(MessageDigest.isEqual(localEphemeral.public.encoded, expectedLocalEphemeral)) {
            "Local ephemeral key does not match transcript"
        }
        require(MessageDigest.isEqual(remoteEphemeralSpki, expectedRemoteEphemeral)) {
            "Remote ephemeral key does not match transcript"
        }

        val transcriptBytes = transcript.bytes()
        val code = transcript.verificationCode()
        require(confirmedVerificationCode == code) { "Out-of-band verification code mismatch" }
        require(SessionAuthenticator.verifySignature(
            localIdentitySpki, transcriptBytes, localSignatureDer
        )) { "Local transcript signature invalid" }
        require(SessionAuthenticator.verifySignature(
            pinnedRemoteIdentitySpki, transcriptBytes, remoteSignatureDer
        )) { "Remote transcript signature invalid" }

        val outboundKey = SessionCrypto.deriveKey(
            localEphemeral, remoteEphemeralSpki, transcriptBytes, localIsInitiator
        )
        val inboundKey = SessionCrypto.deriveKey(
            localEphemeral, remoteEphemeralSpki, transcriptBytes, !localIsInitiator
        )
        return AuthenticatedSessionMaterial(
            sessionId, peerId, code,
            SessionCipher(outboundKey, transcriptBytes),
            SessionCipher(inboundKey, transcriptBytes)
        )
    }

    private fun fingerprint(identitySpki: ByteArray): String {
        require(identitySpki.isNotEmpty() && identitySpki.size <= 2048)
        return MessageDigest.getInstance("SHA-256").digest(identitySpki)
            .joinToString(":") { "%02X".format(it.toInt() and 255) }
    }
}
