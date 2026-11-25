package com.nexalink.app.security

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/** Run on a dedicated transport. The owner must close it on failure and set I/O deadlines. */
internal object WireHandshake {
    private val magic = "NXL1".toByteArray(Charsets.US_ASCII)

    fun initiate(
        input: InputStream,
        output: OutputStream,
        localIdentity: ByteArray,
        pinnedPeerIdentity: ByteArray,
        sign: (SessionTranscript) -> ByteArray,
        confirmCode: (String) -> String?
    ): AuthenticatedSessionMaterial {
        val reader = DataInputStream(input)
        val writer = DataOutputStream(output)
        val ephemeral = SessionCrypto.ephemeralKeyPair()
        val nonce = ByteArray(32).also(SecureRandom()::nextBytes)
        writer.write(magic)
        writer.write(nonce)
        writer.writeField(ephemeral.public.encoded, 2048)
        writer.flush()

        require(reader.readBytesExactly(magic.size).contentEquals(magic)) { "Invalid handshake version" }
        val remoteNonce = reader.readBytesExactly(32)
        val remoteEphemeral = reader.readField(2048)
        val remoteSignature = reader.readField(256)
        val transcript = SessionTranscript(
            localIdentity, pinnedPeerIdentity, ephemeral.public.encoded, remoteEphemeral,
            nonce, remoteNonce
        )
        val transcriptBytes = transcript.bytes()
        require(SessionAuthenticator.verifySignature(pinnedPeerIdentity, transcriptBytes, remoteSignature)) {
            "Peer signature does not match the pinned identity"
        }
        val localSignature = sign(transcript)
        writer.writeField(localSignature, 256)
        writer.flush()
        val code = requireNotNull(confirmCode(transcript.verificationCode())) { "Session declined" }
        return AuthenticatedSessionFactory.establish(
            hexDigest(transcriptBytes, "", false),
            hexDigest(pinnedPeerIdentity, ":", true),
            transcript, localIdentity, pinnedPeerIdentity, ephemeral, remoteEphemeral,
            localSignature, remoteSignature, true, code
        )
    }

    fun initiateWithKeystore(
        input: InputStream,
        output: OutputStream,
        peer: TrustedPeerStore.Peer,
        confirmCode: (String) -> String?
    ): AuthenticatedSessionMaterial = initiate(
        input, output, DeviceIdentityStore().publicKey().encoded,
        Base64.getUrlDecoder().decode(peer.publicKey),
        { Base64.getUrlDecoder().decode(SessionAuthenticator().sign(it)) },
        confirmCode
    )

    private fun DataInputStream.readBytesExactly(size: Int): ByteArray =
        ByteArray(size).also { readFully(it) }

    private fun DataInputStream.readField(max: Int): ByteArray {
        val size = readUnsignedShort()
        require(size in 1..max) { "Invalid handshake field length" }
        return readBytesExactly(size)
    }

    private fun DataOutputStream.writeField(bytes: ByteArray, max: Int) {
        require(bytes.size in 1..max) { "Invalid handshake field length" }
        writeShort(bytes.size)
        write(bytes)
    }

    private fun hexDigest(bytes: ByteArray, separator: String, uppercase: Boolean): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString(separator) {
            (it.toInt() and 255).toString(16).padStart(2, '0').let { hex ->
                if (uppercase) hex.uppercase() else hex
            }
        }
}
