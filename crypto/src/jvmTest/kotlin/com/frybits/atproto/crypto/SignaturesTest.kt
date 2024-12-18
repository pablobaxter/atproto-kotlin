package com.frybits.atproto.crypto

import com.frybits.atproto.crypto.algorithms.ES256
import com.frybits.atproto.crypto.algorithms.ES256K
import com.frybits.atproto.crypto.algorithms.ES256KWithDer
import com.frybits.atproto.crypto.algorithms.ES256WithDer
import com.frybits.atproto.crypto.utils.TestVector
import com.frybits.atproto.crypto.utils.extractPrefixedBytes
import com.frybits.atproto.crypto.utils.parseDidKey
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.fail

class SignaturesTest {

    private val resource = requireNotNull(this::class.java.classLoader.getResource("signature-fixtures.json"))
    @OptIn(ExperimentalSerializationApi::class)
    private val vectors = resource.openStream().use {
        Json {
            ignoreUnknownKeys = true
        }.decodeFromStream<List<TestVector>>(it)
    }

    @OptIn(ExperimentalStdlibApi::class, ExperimentalEncodingApi::class)
    @Test
    fun `verifies secp256k1 and P-256 test vectors`() = runBlocking {
        vectors.forEach { vector ->
            val decoder = Base64.withPadding(Base64.PaddingOption.ABSENT)
            val messageBytes = decoder.decode(vector.messageBase64)
            val signatureBytes = decoder.decode(vector.signatureBase64)

            val keyBytes = vector.publicKeyMultibase.extractPrefixedBytes()

            val didKey = vector.publicKeyDid.parseDidKey()

            assertContentEquals(keyBytes, didKey.second)

            val algo = when (vector.algorithm) {
                ES256::class.java.simpleName -> ES256
                ES256K::class.java.simpleName -> ES256K
                else -> fail()
            }
            val verified = algo.verify(keyBytes, messageBytes, signatureBytes)
            assertEquals(vector.validSignature, verified)


        }
    }

    @OptIn(ExperimentalEncodingApi::class)
    @Test
    fun `verifies high-s signatures with explicit option`() = runBlocking {
        val highSVectors = vectors.filter { it.tags.contains("high-s") }
        assertTrue { highSVectors.size >= 2 }
        highSVectors.forEach { vector ->
            val decoder = Base64.withPadding(Base64.PaddingOption.ABSENT)
            val messageBytes = decoder.decode(vector.messageBase64)
            val signatureBytes = decoder.decode(vector.signatureBase64)

            val keyBytes = vector.publicKeyMultibase.extractPrefixedBytes()
            val did = vector.publicKeyDid.parseDidKey()

            assertContentEquals(keyBytes, did.second)

            val algo = when (vector.algorithm) {
                ES256::class.java.simpleName -> ES256
                ES256K::class.java.simpleName -> ES256K
                else -> fail()
            }

            val verified = algo.verify(keyBytes, messageBytes, signatureBytes, useLowS = false)

            assertTrue(verified)

            assertFalse(vector.validSignature)
        }
    }

    @OptIn(ExperimentalEncodingApi::class)
    @Test
    fun `verifies der-encoded signatures with explicit option`() = runBlocking {
        val derEncoded = vectors.filter { it.tags.contains("der-encoded") }
        assertTrue { derEncoded.size >= 2 }
        derEncoded.forEach { vector ->
            val decoder = Base64.withPadding(Base64.PaddingOption.ABSENT)
            val messageBytes = decoder.decode(vector.messageBase64)
            val signatureBytes = decoder.decode(vector.signatureBase64)

            val keyBytes = vector.publicKeyMultibase.extractPrefixedBytes()
            val did = vector.publicKeyDid.parseDidKey()

            assertContentEquals(keyBytes, did.second)

            val algo = when (vector.algorithm) {
                ES256::class.java.simpleName -> ES256WithDer
                ES256K::class.java.simpleName -> ES256KWithDer
                else -> fail()
            }

            val verified = algo.verify(keyBytes, messageBytes, signatureBytes, useLowS = false)

            assertTrue(verified)

            assertFalse(vector.validSignature)
        }
    }

}
