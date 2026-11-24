package com.nexalink.app.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class ManualPairingTest {
    private val keyGenerator = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }
    private val peerKey = keyGenerator.generateKeyPair()
    private val peer = invitation(peerKey.public.encoded)
    private val localFingerprint = invitation(keyGenerator.generateKeyPair().public.encoded).fingerprint()
    private var time = 1000L
    private val pairing = ManualPairing(localFingerprint, peer, { time })

    @Test fun validatesOnlyTheCurrentChallengeAndConsumesIt() {
        val first = pairing.createChallenge()
        val second = pairing.createChallenge()
        assertFalse(pairing.verify(sign(first)))
        assertFalse(pairing.verify(sign(second, peer.fingerprint())))
        val response = sign(second)
        assertTrue(pairing.verify(response))
        assertFalse(pairing.verify(response))
    }

    @Test fun rejectsAnExpiredChallengeAndSelfPairing() {
        val response = sign(pairing.createChallenge())
        time += 120_000
        assertFalse(pairing.verify(response))
        assertThrows(IllegalArgumentException::class.java) {
            ManualPairing(peer.fingerprint(), peer, { time })
        }
    }

    private fun sign(challenge: String, verifier: String = localFingerprint): String {
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(peerKey.private)
            update("NexaLink identity proof v1\u0000".toByteArray(Charsets.UTF_8))
            update(ManualPairing.boundChallenge(challenge, verifier, peer.fingerprint()))
            sign()
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signature)
    }

    private fun invitation(spki: ByteArray) =
        PairingInvitation(1, "Device", Base64.getUrlEncoder().withoutPadding().encodeToString(spki))
}
