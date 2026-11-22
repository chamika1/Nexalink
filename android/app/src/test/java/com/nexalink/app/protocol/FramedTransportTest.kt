package com.nexalink.app.protocol

import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class FramedTransportTest {
    @Test fun rejectsOversizedFrameBeforeReadingBody() {
        val header = byteArrayOf(0, 1, 17, 113) // 70,001 bytes
        assertThrows(IllegalArgumentException::class.java) {
            FramedTransport.read(ByteArrayInputStream(header))
        }
    }

    @Test fun rejectsZeroLengthFrame() {
        assertThrows(IllegalArgumentException::class.java) {
            FramedTransport.read(ByteArrayInputStream(byteArrayOf(0, 0, 0, 0)))
        }
    }

    @Test fun writeRejectsUnknownMessageKind() {
        assertThrows(IllegalArgumentException::class.java) {
            FramedTransport.write(
                ByteArrayOutputStream(),
                Envelope(1, "remote_execute", "session-12345678", "")
            )
        }
    }
}
