package com.frybits.atproto.crypto.utils

import kotlinx.serialization.Serializable

@Serializable
data class TestVector(
    val algorithm: String,
    val publicKeyDid: String,
    val publicKeyMultibase: String,
    val messageBase64: String,
    val signatureBase64: String,
    val validSignature: Boolean,
    val tags: List<String>
)
