package com.nexalink.app.protocol

import org.json.JSONObject

/** Transport-neutral JSON envelope. This does not encrypt its payload. */
data class Envelope(
    val version: Int,
    val kind: String,
    val sessionId: String,
    val payload: String
) {
    fun validate() {
        require(version == 1) { "Unsupported version" }
        require(kind in VALID_KINDS) { "Unknown kind" }
        require(sessionId.length in 8..128) { "Invalid session id" }
        require(payload.toByteArray(Charsets.UTF_8).size <= 65_536) { "Payload too large" }
    }

    fun toJson(): String {
        validate()
        return JSONObject().put("version", version).put("kind", kind)
            .put("session_id", sessionId).put("payload", payload).toString()
    }

    companion object {
        private val VALID_KINDS = setOf(
            "hello", "pairing_request", "pairing_response", "encrypted_data", "disconnect"
        )

        fun fromJson(raw: String): Envelope {
            require(raw.toByteArray(Charsets.UTF_8).size <= 70_000) { "Envelope too large" }
            val json = JSONObject(raw)
            require(json.length() == 4) { "Unexpected fields" }
            return Envelope(
                json.getInt("version"), json.getString("kind"),
                json.getString("session_id"), json.getString("payload")
            ).also { it.validate() }
        }
    }
}
