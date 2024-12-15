package com.frybits.atproto.crypto

interface Signer {

    val jwtAlg: String

    suspend fun sign(msg: ByteArray) : ByteArray
}
