package com.nexalink.app.protocol

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream

/** Binary framing only. Caller must establish authenticated encryption first. */
object FramedTransport {
    private const val MAX_WIRE_BYTES = 70_000

    fun write(output: OutputStream, message: Envelope) {
        val bytes = message.toJson().toByteArray(Charsets.UTF_8)
        require(bytes.size in 1..MAX_WIRE_BYTES)
        val stream = DataOutputStream(output)
        stream.writeInt(bytes.size)
        stream.write(bytes)
        stream.flush()
    }

    fun read(input: InputStream): Envelope {
        val stream = DataInputStream(input)
        val size = stream.readInt()
        require(size in 1..MAX_WIRE_BYTES) { "Invalid frame length" }
        val bytes = ByteArray(size)
        stream.readFully(bytes)
        return Envelope.fromJson(bytes.toString(Charsets.UTF_8))
    }
}
