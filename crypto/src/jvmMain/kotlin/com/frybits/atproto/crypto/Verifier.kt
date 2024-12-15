package com.frybits.atproto.crypto

interface Verifier {

    suspend fun verify(pubDid: String, data: ByteArray, sig: ByteArray): Boolean
}
