package com.nexalink.app.protocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class EnvelopeTest {
    @Test fun validatesKnownMessage() {
        val message = Envelope(1, "hello", "session-12345678", "")
        message.validate()
        assertEquals("hello", message.kind)
    }

    @Test fun rejectsUnknownMessage() {
        assertThrows(IllegalArgumentException::class.java) {
            Envelope(1, "remote_execute", "session-12345678", "").validate()
        }
    }

    @Test fun rejectsOversizedPayload() {
        assertThrows(IllegalArgumentException::class.java) {
            Envelope(1, "encrypted_data", "session-12345678", "x".repeat(65537)).validate()
        }
    }
}
