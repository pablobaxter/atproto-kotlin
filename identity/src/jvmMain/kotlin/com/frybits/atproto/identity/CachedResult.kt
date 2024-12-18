package com.frybits.atproto.identity

import com.frybits.atproto.common.DidDocument
import kotlinx.serialization.Serializable

@Serializable
data class CachedResult(
    val did: String,
    val doc: DidDocument,
    val updatedAt: Long,
    val stale: Boolean,
    val expired: Boolean
)
