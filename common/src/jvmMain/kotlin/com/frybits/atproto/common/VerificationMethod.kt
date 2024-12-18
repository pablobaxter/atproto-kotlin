package com.frybits.atproto.common

import kotlinx.serialization.Serializable

@Serializable
data class VerificationMethod(
    val id: String,
    val type: String,
    val controller: String,
    val publicKeyMultiBase: String
)