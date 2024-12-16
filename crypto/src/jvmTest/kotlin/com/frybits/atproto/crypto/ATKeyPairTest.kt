package com.frybits.atproto.crypto

import kotlinx.coroutines.runBlocking
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ATKeyPairTest {

    @Test
    fun `secp256k1 - has the same DID on import`() = runBlocking {
        val keypair = K256KeyPair(true)
        val exported = keypair.export()
        val imported = K256KeyPair(exported, true)
        assertEquals(keypair.did, imported.did)
    }

    @Test
    fun `secp256k1 - produces a valid signature`() = runBlocking {
        val keypair = K256KeyPair(true)
        val exported = keypair.export()
        val imported = K256KeyPair(exported, true)

        val data = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        val sig = imported.sign(data)

        val validSig = keypair.verify(data, sig)

        assertTrue(validSig)
    }

    @Test
    fun `secp256k1 - produces a valid signature on a large array`() = runBlocking {
        val keypair = K256KeyPair(true)
        val exported = keypair.export()
        val imported = K256KeyPair(exported, true)

        val bytes = Random.nextBytes(8192)

        val sig = imported.sign(bytes)

        val validSig = keypair.verify(bytes, sig)

        assertTrue(validSig)
    }

    @Test
    fun `p256 - has the same DID on import`() = runBlocking {
        val keypair = P256KeyPair(true)
        val exported = keypair.export()
        val imported = P256KeyPair(exported, true)
        assertEquals(keypair.did, imported.did)
    }

    @Test
    fun `p256 - produces a valid signature`() = runBlocking {
        val keypair = P256KeyPair(true)
        val exported = keypair.export()
        val imported = P256KeyPair(exported, true)

        val data = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        val sig = imported.sign(data)

        val validSig = keypair.verify(data, sig)

        assertTrue(validSig)
    }

    @OptIn(ExperimentalEncodingApi::class)
    @Test
    fun `p256 - produces a valid signature on a large array`() = runBlocking {
        val keypair = P256KeyPair(true) as ECDSAKeyPair
        val exported = keypair.export()
        val imported = P256KeyPair(exported, true)

        val bytes = Random.nextBytes(8192)

        val sig = imported.sign(bytes)

        val validSig = keypair.verify(bytes, sig)

        assertTrue(validSig)
    }
}
