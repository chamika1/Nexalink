package com.nexalink.app.protocol

import com.nexalink.app.security.SessionCipher
import java.io.InputStream
import java.io.OutputStream
import java.util.Base64

/**
 * Wire adapter for an authenticated, consented session.
 * Never use with an unverified peer. Does not open sockets or grant access.
 */
object SecureFrame {
    fun send(
        output: OutputStream,
        cipher: SessionCipher,
        sessionId: String,
        plaintext: ByteArray
    ) {
        val frame = cipher.encrypt(plaintext)
        val payload = Base64.getUrlEncoder().withoutPadding().encodeToString(frame)
        FramedTransport.write(output, Envelope(1, "encrypted_data", sessionId, payload))
    }

    fun receive(
        input: InputStream,
        cipher: SessionCipher,
        expectedSessionId: String
    ): ByteArray {
        val message = FramedTransport.read(input)
        require(message.kind == "encrypted_data" && message.sessionId == expectedSessionId) {
            "Unexpected session or message kind"
        }
        val frame = Base64.getUrlDecoder().decode(message.payload)
        return cipher.decrypt(frame)
    }
}
