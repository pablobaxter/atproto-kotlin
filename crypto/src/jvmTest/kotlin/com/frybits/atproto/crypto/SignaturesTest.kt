package com.frybits.atproto.crypto

import com.frybits.atproto.crypto.utils.TestVector
import com.frybits.atproto.crypto.utils.extractPrefixedBytes
import com.frybits.atproto.crypto.utils.parseDidKey
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

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

            val algo = Algorithm.valueOf(vector.algorithm)
            val verified = algo.verify(keyBytes, messageBytes, signatureBytes)
            assertEquals(vector.validSignature, verified)
        }
    }
}
