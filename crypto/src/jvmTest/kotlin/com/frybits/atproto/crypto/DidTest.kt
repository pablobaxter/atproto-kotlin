package com.frybits.atproto.crypto

import com.frybits.atproto.crypto.algorithms.ES256
import com.frybits.atproto.crypto.algorithms.ES256K
import com.frybits.atproto.crypto.utils.formatDidKey
import com.frybits.atproto.crypto.utils.parseDidKey
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.fail

@OptIn(ExperimentalSerializationApi::class)
class DidTest {

    val secpTestVectorsJsonResource = requireNotNull(this::class.java.classLoader.getResource("w3c_didkey_K256.json"))
    val secpTestVectors = secpTestVectorsJsonResource.openStream().use {
        Json.decodeFromStream<List<Map<String, String>>>(it)
    }

    val p256TestVectorsJsonResource = requireNotNull(this::class.java.classLoader.getResource("w3c_didkey_P256.json"))
    val p256TestVectors = p256TestVectorsJsonResource.openStream().use {
        Json.decodeFromStream<List<Map<String, String>>>(it)
    }

    @Test
    fun `secp256k1 did key - derives the correct DID from the privatekey`() = runBlocking {
        secpTestVectors.forEach {
            val seed = it["privateKeyBytesHex"] ?: fail()
            val id = it["publicDidKey"] ?: fail()

            val keyPair = K256KeyPair(seed)
            assertEquals(id, keyPair.did)
        }
    }

    @Test
    fun `secp256k1 did key - converts between bytes and did`() = runBlocking {
        secpTestVectors.forEach {
            val seed = it["privateKeyBytesHex"] ?: fail()
            val id = it["publicDidKey"] ?: fail()

            val keyPair = K256KeyPair(seed) as ECDSAKeyPair
            val generatedDid = ES256K.formatDidKey(keyPair.publicKeyParam.q.getEncoded(true))
            assertEquals(id, generatedDid)
            val (algo, bytes) = generatedDid.parseDidKey()
            assertEquals(ES256K, algo)
            assertContentEquals(bytes, keyPair.publicKeyParam.q.getEncoded(true))
        }
    }

    @Test
    fun `P-256 did key - derives the correct DID from the JWK`() = runBlocking {
        p256TestVectors.forEach { vector ->
            val key = vector["privateKeyBytesBase58"] ?: fail()
            val id = vector["publicDidKey"] ?: fail()

            val keyPair = P256KeyPair(key)
            assertEquals(id, keyPair.did)
        }
    }

    @Test
    fun `P-256 did key - converts between bytes and did`() = runBlocking {
        p256TestVectors.forEach { vector ->
            val key = vector["privateKeyBytesBase58"] ?: fail()
            val id = vector["publicDidKey"] ?: fail()

            val keyPair = P256KeyPair(key) as ECDSAKeyPair
            val generatedDid = ES256.formatDidKey(keyPair.publicKeyParam.q.getEncoded(true))
            assertEquals(id, generatedDid)
            val (algo, bytes) = generatedDid.parseDidKey()
            assertEquals(ES256, algo)
            assertContentEquals(bytes, keyPair.publicKeyParam.q.getEncoded(true))
        }
    }
}
