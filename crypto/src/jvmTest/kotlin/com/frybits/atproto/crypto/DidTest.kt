package com.frybits.atproto.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.fail

// did:key secp256k1 test vectors from W3C
// https://github.com/w3c-ccg/did-method-key/blob/main/test-vectors/secp256k1.json
private val secpTestVectors = listOf(
    mapOf(
        "seed" to "9085d2bef69286a6cbb51623c8fa258629945cd55ca705cc4e66700396894e0c",
        "id" to "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme"
    ),
    mapOf(
        "seed" to "f0f4df55a2b3ff13051ea814a8f24ad00f2e469af73c363ac7e9fb999a9072ed",
        "id" to "did:key:zQ3shtxV1FrJfhqE1dvxYRcCknWNjHc3c5X1y3ZSoPDi2aur2"
    ),
    mapOf(
        "seed" to "6b0b91287ae3348f8c2f2552d766f30e3604867e34adc37ccbb74a8e6b893e02",
        "id" to "did:key:zQ3shZc2QzApp2oymGvQbzP8eKheVshBHbU4ZYjeXqwSKEn6N"
    ),
    mapOf(
        "seed" to "c0a6a7c560d37d7ba81ecee9543721ff48fea3e0fb827d42c1868226540fac15",
        "id" to "did:key:zQ3shadCps5JLAHcZiuX5YUtWHHL8ysBJqFLWvjZDKAWUBGzy"
    ),
    mapOf(
        "seed" to "175a232d440be1e0788f25488a73d9416c04b6f924bea6354bf05dd2f1a75133",
        "id" to "did:key:zQ3shptjE6JwdkeKN4fcpnYQY3m9Cet3NiHdAfpvSUZBFoKBj"
    )
)

// did:key p-256 test vectors from W3C
// https://github.com/w3c-ccg/did-method-key/blob/main/test-vectors/nist-curves.json
private val p256TestVectors = mapOf(
    "privateKeyBase58" to "9p4VRzdmhsnq869vQjVCTrRry7u4TtfRxhvBFJTGU2Cp",
    "id" to "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb"
)

class DidTest {

    @Test
    fun `secp256k1 did key - derives the correct DID from the privatekey`() {
        secpTestVectors.forEach {
            val seed = it["seed"] ?: fail()
            val id = it["id"] ?: fail()

            val algorithm = K256Algorithm(seed)
            assertEquals(id, algorithm.did)
        }
    }

    @Test
    fun `P-256 did key - derives the correct DID from the JWK`() {
        val key = p256TestVectors["privateKeyBase58"] ?: fail()
        val id = p256TestVectors["id"] ?: fail()

        val algorithm = P256Algorithm(key)
        assertEquals(id, algorithm.did)
    }
}