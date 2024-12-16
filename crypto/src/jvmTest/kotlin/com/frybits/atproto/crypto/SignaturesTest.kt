package com.frybits.atproto.crypto

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
        Json.decodeFromStream<JsonArray>(it)
    }

    @OptIn(ExperimentalStdlibApi::class, ExperimentalEncodingApi::class)
    @Test
    fun `verifies secp256k1 and P-256 test vectors`() = runBlocking {
        vectors.forEach { vector ->
            val json = vector.jsonObject
            val decoder = Base64.withPadding(Base64.PaddingOption.ABSENT)
            val messageBytes = decoder.decode(requireNotNull(json["messageBase64"]?.jsonPrimitive?.content))
            val signatureBytes = decoder.decode(requireNotNull(json["signatureBase64"]?.jsonPrimitive?.content))

            val keyBytes = requireNotNull(json["publicKeyMultibase"]?.jsonPrimitive?.content).extractPrefixedBytes()

            val didKey = requireNotNull(json["publicKeyDid"]?.jsonPrimitive?.content).parseDidKey()

            assertContentEquals(keyBytes, didKey.second)

            if (json["algorithm"]?.jsonPrimitive?.content == Algorithm.ES256.name) {
                val verified = Algorithm.ES256.verify(keyBytes, messageBytes, signatureBytes)
                println(json["validSignature"])
                assertEquals(json["validSignature"]?.jsonPrimitive?.content.toBoolean(), verified)
            }
        }
    }
}
