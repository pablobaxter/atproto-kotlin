package com.frybits.atproto.crypto

interface Signer {

    val jwtAlg: JWTAlgorithm

    suspend fun sign(msg: ByteArray) : ByteArray
}
