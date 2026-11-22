package com.nexalink.app.security

/** Each sensitive capability requires separate, expiring, revocable consent. */
enum class SessionCapability { CHAT, LOCATION, SCREEN_VIEW, REMOTE_INPUT }

data class CapabilityGrant(
    val capability: SessionCapability,
    val peerId: String,
    val expiresAtMillis: Long,
    val approvedByUser: Boolean
) {
    fun isActive(nowMillis: Long): Boolean =
        approvedByUser && nowMillis < expiresAtMillis
}

class SessionConsent {
    private val grants = mutableMapOf<Pair<String, SessionCapability>, CapabilityGrant>()

    @Synchronized
    fun approve(
        peerId: String,
        capability: SessionCapability,
        durationMillis: Long,
        nowMillis: Long,
        approvedByUser: Boolean
    ) {
        require(peerId.isNotBlank())
        require(approvedByUser) { "Explicit user approval required" }
        require(durationMillis in 1..3_600_000L) { "Maximum grant is one hour" }
        grants[peerId to capability] = CapabilityGrant(
            capability, peerId, nowMillis + durationMillis, true
        )
    }

    @Synchronized
    fun allowed(peerId: String, capability: SessionCapability, nowMillis: Long): Boolean =
        grants[peerId to capability]?.isActive(nowMillis) == true

    @Synchronized
    fun revoke(peerId: String, capability: SessionCapability) {
        grants.remove(peerId to capability)
    }

    @Synchronized
    fun revokeAll(peerId: String) {
        grants.keys.removeAll { it.first == peerId }
    }
}
