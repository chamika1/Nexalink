package com.nexalink.app.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyPair
import java.security.Signature
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit

class WireHandshakeTest {
    @Test fun authenticatesPinnedResponderAndDerivesMatchingCipher() {
        val local = SessionCrypto.ephemeralKeyPair()
        val remote = SessionCrypto.ephemeralKeyPair()
        val loopback = InetAddress.getLoopbackAddress()
        ServerSocket(0, 1, loopback).use { listener ->
            listener.soTimeout = 3000
            val responder = FutureTask {
                listener.accept().use { socket ->
                    socket.soTimeout = 3000
                    val input = DataInputStream(socket.getInputStream())
                    val output = DataOutputStream(socket.getOutputStream())
                    assertEquals("NXL1", String(ByteArray(4).also(input::readFully), Charsets.US_ASCII))
                    val nonce = ByteArray(32).also(input::readFully)
                    val localEphemeral = ByteArray(input.readUnsignedShort()).also(input::readFully)
                    val remoteEphemeral = SessionCrypto.ephemeralKeyPair()
                    val remoteNonce = ByteArray(32) { 7 }
                    val transcript = SessionTranscript(
                        local.public.encoded, remote.public.encoded, localEphemeral,
                        remoteEphemeral.public.encoded, nonce, remoteNonce
                    )
                    val signature = sign(remote, transcript)
                    output.writeBytes("NXL1")
                    output.write(remoteNonce)
                    output.writeShort(remoteEphemeral.public.encoded.size)
                    output.write(remoteEphemeral.public.encoded)
                    output.writeShort(signature.size)
                    output.write(signature)
                    output.flush()
                    val peerSignature = ByteArray(input.readUnsignedShort()).also(input::readFully)
                    check(SessionAuthenticator.verifySignature(local.public.encoded, transcript.bytes(), peerSignature))
                    val key = SessionCrypto.deriveKey(remoteEphemeral, localEphemeral, transcript.bytes(), true)
                    val encrypted = ByteArray(input.readUnsignedShort()).also(input::readFully)
                    transcript.verificationCode() to SessionCipher(key, transcript.bytes()).decrypt(encrypted)
                }
            }
            Thread(responder).apply { isDaemon = true }.start()
            Socket(loopback, listener.localPort).use { socket ->
                socket.soTimeout = 3000
                val material = WireHandshake.initiate(
                    socket.getInputStream(), socket.getOutputStream(),
                    local.public.encoded, remote.public.encoded,
                    { sign(local, it) }, { it }
                )
                val payload = "wire test".toByteArray()
                val encrypted = material.outboundCipher.encrypt(payload)
                DataOutputStream(socket.getOutputStream()).apply {
                    writeShort(encrypted.size)
                    write(encrypted)
                    flush()
                }
                val (code, decrypted) = responder.get(3, TimeUnit.SECONDS)
                assertEquals(code, material.verificationCode)
                assertArrayEquals(payload, decrypted)
            }
        }
    }

    @Test fun rejectsOversizedEphemeralFieldBeforeSigning() {
        val local = SessionCrypto.ephemeralKeyPair()
        val remote = SessionCrypto.ephemeralKeyPair()
        val response = ByteArrayOutputStream().apply {
            DataOutputStream(this).apply {
                writeBytes("NXL1")
                write(ByteArray(32))
                writeShort(2049)
            }
        }.toByteArray()
        assertThrows(IllegalArgumentException::class.java) {
            WireHandshake.initiate(
                ByteArrayInputStream(response), ByteArrayOutputStream(),
                local.public.encoded, remote.public.encoded,
                { error("Must reject before signing") }, { error("Must reject before prompting") }
            )
        }
    }

    private fun sign(identity: KeyPair, transcript: SessionTranscript): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(identity.private)
            update(transcript.bytes())
            sign()
        }
}
