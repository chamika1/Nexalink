package com.nexalink.app.security

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Local registry of explicitly approved peer public keys.
 * This registry is NOT an authentication substitute: verify signatures
 * against the stored key on every new transport session.
 */
class TrustedPeerStore(context: Context) {
    private val prefs = context.getSharedPreferences("nexalink_trusted_peers_v1", Context.MODE_PRIVATE)
    private val key = "peers"

    data class Peer(val id: String, val name: String, val publicKey: String, val addedAt: Long)

    @Synchronized fun list(): List<Peer> {
        val raw = prefs.getString(key, "[]") ?: "[]"
        return runCatching {
            val arr = JSONArray(raw)
            (0 until arr.length()).map { index ->
                val obj = arr.getJSONObject(index)
                Peer(obj.getString("id"), obj.getString("name"), obj.getString("publicKey"), obj.getLong("addedAt"))
            }
        }.getOrDefault(emptyList())
    }

    @Synchronized fun addVerified(name: String, encodedPublicKey: String, confirmedByUser: Boolean): Peer {
        require(confirmedByUser) { "Explicit user approval required" }
        val invitation = PairingInvitation(1, name, encodedPublicKey)
        invitation.serialize()
        val id = invitation.fingerprint()
        val peer = Peer(id, name, encodedPublicKey, System.currentTimeMillis())
        val all = list().filterNot { it.id == id } + peer
        persist(all)
        return peer
    }

    @Synchronized fun revoke(id: String): Boolean {
        val current = list()
        val remaining = current.filterNot { it.id == id }
        if (remaining.size == current.size) return false
        persist(remaining)
        return true
    }

    private fun persist(peers: List<Peer>) {
        val arr = JSONArray()
        peers.forEach {
            arr.put(JSONObject().put("id", it.id).put("name", it.name)
                .put("publicKey", it.publicKey).put("addedAt", it.addedAt))
        }
        check(prefs.edit().putString(key, arr.toString()).commit()) { "Could not persist trusted peers" }
    }
}
