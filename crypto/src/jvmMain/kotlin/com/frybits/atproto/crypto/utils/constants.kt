package com.frybits.atproto.crypto.utils

internal val P256_DID_PREFIX = byteArrayOf(0x80.toByte(), 0x24)
internal val SECP256K1_DID_PREFIX = byteArrayOf(0xe7.toByte(), 0x01)

internal const val BASE58_MULTIBASE_PREFIX = 'z'
internal const val DID_KEY_PREFIX = "did:key:"

internal const val P256_JWT_ALG = "ES256"
internal const val SECP256K1_JWT_ALG = "ES256K"
