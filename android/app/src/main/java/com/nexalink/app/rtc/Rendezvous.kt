package com.nexalink.app.rtc

import kotlinx.coroutines.delay
import org.json.JSONObject
import org.webrtc.SessionDescription
import java.net.URL
import java.util.Base64
import javax.net.ssl.HttpsURLConnection

internal class Rendezvous(address: String) {
    private val base = URL(address.trimEnd('/')).also {
        require(it.protocol == "https" && it.host.isNotEmpty() &&
            it.userInfo == null && it.query == null && it.ref == null)
    }

    data class Room(val id: String, val token: String)

    fun create(): Pair<Room, String> {
        val result = JSONObject(request("POST", "/rooms", null, null, 201).second)
        val id = result.getString("room")
        val initiator = result.getString("initiator_token")
        val responder = result.getString("responder_token")
        require(validToken(id) && validToken(initiator) && validToken(responder))
        return Room(id, initiator) to "$id.$responder"
    }

    fun join(code: String): Room {
        val parts = code.split('.', limit = 2)
        require(parts.size == 2 && parts.all(::validToken)) { "Invalid room code" }
        return Room(parts[0], parts[1])
    }

    fun publish(room: Room, description: SessionDescription) {
        val type = description.type.canonicalForm()
        val body = JSONObject().put("type", type).put("sdp", description.description).toString()
        request("PUT", "/rooms/${room.id}/$type", room.token, body, 204)
    }

    suspend fun waitFor(room: Room, type: SessionDescription.Type): SessionDescription {
        while (true) {
            val (status, body) = request("GET", "/rooms/${room.id}/${type.canonicalForm()}", room.token, null, 200, 204)
            if (status == 200) {
                val parsed = JSONObject(body)
                require(parsed.getString("type") == type.canonicalForm())
                return SessionDescription(type, parsed.getString("sdp"))
            }
            delay(1000)
        }
    }

    private fun request(
        method: String, path: String, token: String?, body: String?, vararg expected: Int
    ): Pair<Int, String> {
        val connection = URL(base.toString() + path).openConnection() as HttpsURLConnection
        try {
            connection.requestMethod = method
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 5000
            connection.readTimeout = 5000
            token?.let { connection.setRequestProperty("Authorization", "Bearer $it") }
            if (body != null) {
                val bytes = body.toByteArray()
                require(bytes.size <= LIMIT)
                connection.doOutput = true
                connection.setFixedLengthStreamingMode(bytes.size)
                connection.outputStream.use { it.write(bytes) }
            }
            val status = connection.responseCode
            check(status in expected) { "Signaling returned HTTP $status" }
            if (status == 204) return status to ""
            val reply = connection.inputStream.use { input ->
                val buffer = ByteArray(LIMIT + 1)
                var size = 0
                while (size < buffer.size) {
                    val count = input.read(buffer, size, buffer.size - size)
                    if (count < 0) break
                    size += count
                }
                require(size <= LIMIT)
                String(buffer, 0, size, Charsets.UTF_8)
            }
            return status to reply
        } finally {
            connection.disconnect()
        }
    }

    private fun validToken(value: String): Boolean = value.length == 43 && runCatching {
        val bytes = Base64.getUrlDecoder().decode(value)
        bytes.size == 32 && Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) == value
    }.getOrDefault(false)

    companion object {
        private const val LIMIT = 64 * 1024
    }
}
