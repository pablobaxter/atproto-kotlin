package com.frybits.atproto.common

import kotlinx.serialization.Serializable

@Serializable
data class DidDocument(
    val id: String,
    val alsoKnownAs: List<String>,
    val verificationMethod: List<VerificationMethod>,
    val service: List<Service>
)
