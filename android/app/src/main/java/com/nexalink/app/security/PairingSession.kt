package com.nexalink.app.security

/**
 * UI-only pairing lifecycle. Never mark a device trusted on QR scan alone.
 * Transport authentication and signature challenges are future work.
 */
enum class PairingStatus {
    IDLE,
    INVITATION_SCANNED,
    AWAITING_LOCAL_APPROVAL,
    AWAITING_REMOTE_APPROVAL,
    AWAITING_FINGERPRINT_VERIFICATION,
    VERIFIED,
    REJECTED,
    EXPIRED
}

data class PairingSession(
    val peerName: String,
    val peerFingerprint: String,
    val status: PairingStatus = PairingStatus.INVITATION_SCANNED
) {
    fun requestApproval(): PairingSession {
        require(status == PairingStatus.INVITATION_SCANNED)
        return copy(status = PairingStatus.AWAITING_LOCAL_APPROVAL)
    }

    fun approveLocally(): PairingSession {
        require(status == PairingStatus.AWAITING_LOCAL_APPROVAL)
        return copy(status = PairingStatus.AWAITING_REMOTE_APPROVAL)
    }

    fun remoteApproved(): PairingSession {
        require(status == PairingStatus.AWAITING_REMOTE_APPROVAL)
        return copy(status = PairingStatus.AWAITING_FINGERPRINT_VERIFICATION)
    }

    fun verifyFingerprint(): PairingSession {
        require(status == PairingStatus.AWAITING_FINGERPRINT_VERIFICATION)
        return copy(status = PairingStatus.VERIFIED)
    }

    fun reject(): PairingSession = copy(status = PairingStatus.REJECTED)
}
