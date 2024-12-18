package com.frybits.atproto.common

import kotlinx.serialization.Serializable

@Serializable
data class Service(
    val id: String,
    val type: String,
    val serviceEndpoint: String
)
