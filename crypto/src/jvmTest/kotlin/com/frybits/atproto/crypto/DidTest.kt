package com.frybits.atproto.crypto

import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.fail

class DidTest {

    @Test
    fun `secp256k1 did key - derives the correct DID from the privatekey`() = runBlocking {
        secpTestVectors.forEach {
            val seed = it["seed"] ?: fail()
            val id = it["id"] ?: fail()

            val algorithm = K256Algorithm(seed)
            assertEquals(id, algorithm.did)
        }
    }

    @Test
    fun `secp256k1 did key - converts between bytes and did`() = runBlocking {
        secpTestVectors.forEach {
            val seed = it["seed"] ?: fail()
            val id = it["id"] ?: fail()

            val algorithm = K256Algorithm(seed)
            assertEquals(id, algorithm.did)
        }
    }

    @Test
    fun `P-256 did key - derives the correct DID from the JWK`() = runBlocking {
        val key = p256TestVectors["privateKeyBase58"] ?: fail()
        val id = p256TestVectors["id"] ?: fail()

        val algorithm = P256Algorithm(key)
        assertEquals(id, algorithm.did)
    }
}
