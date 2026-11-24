package com.nexalink.app.security

/** Each capability requires separate consent scoped to one peer AND one session. */
enum class SessionCapability { CHAT, LOCATION, SCREEN_VIEW, REMOTE_INPUT }

data class CapabilityGrant(
    val capability: SessionCapability,
    val peerId: String,
    val sessionId: String,
    val expiresAtMillis: Long,
    val approvedByUser: Boolean
) {
    fun isActive(nowMillis: Long): Boolean =
        approvedByUser && nowMillis < expiresAtMillis
}

class SessionConsent {
    private val grants = mutableMapOf<Triple<String, String, SessionCapability>, CapabilityGrant>()

    @Synchronized
    fun approve(
        peerId: String,
        sessionId: String,
        capability: SessionCapability,
        durationMillis: Long,
        nowMillis: Long,
        approvedByUser: Boolean
    ) {
        require(peerId.isNotBlank() && peerId.length <= 128)
        require(sessionId.length in 8..128) { "Invalid session id" }
        require(approvedByUser) { "Explicit user approval required" }
        require(durationMillis in 1..900_000L) { "Maximum grant is fifteen minutes" }
        require(nowMillis >= 0) { "Invalid clock value" }
        val expiry = Math.addExact(nowMillis, durationMillis)
        grants[Triple(peerId, sessionId, capability)] = CapabilityGrant(
            capability, peerId, sessionId, expiry, true
        )
    }

    @Synchronized
    fun allowed(
        peerId: String,
        sessionId: String,
        capability: SessionCapability,
        nowMillis: Long
    ): Boolean = grants[Triple(peerId, sessionId, capability)]?.isActive(nowMillis) == true

    @Synchronized
    fun revoke(peerId: String, sessionId: String, capability: SessionCapability) {
        grants.remove(Triple(peerId, sessionId, capability))
    }

    @Synchronized
    fun revokeSession(peerId: String, sessionId: String) {
        grants.keys.removeAll { it.first == peerId && it.second == sessionId }
    }

    @Synchronized
    fun revokeAll(peerId: String) {
        grants.keys.removeAll { it.first == peerId }
    }
}
