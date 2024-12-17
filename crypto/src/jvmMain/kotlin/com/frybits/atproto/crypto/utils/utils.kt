package com.frybits.atproto.crypto.utils

import com.frybits.atproto.crypto.algorithms.Algorithm
import com.frybits.atproto.crypto.algorithms.ES256
import com.frybits.atproto.crypto.algorithms.ES256K
import com.frybits.atproto.crypto.algorithms.EllipticCurveAlgorithm
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private const val BASE58_MULTIBASE_PREFIX = "z"
private const val DID_KEY_PREFIX = "did:key:"

fun String.extractMultikey(): String {
    require(startsWith(DID_KEY_PREFIX)) { "Incorrect prefix for did:key: $this" }
    return removePrefix(DID_KEY_PREFIX)
}

fun String.extractPrefixedBytes(): ByteArray {
    require(startsWith(BASE58_MULTIBASE_PREFIX)) { "Incorrect prefix for multikey: $this" }
    return removePrefix(BASE58_MULTIBASE_PREFIX).decodeBase58()
}

fun Algorithm.formatDidKey(keyBytes: ByteArray): String {
    return "$DID_KEY_PREFIX${formatMultikey(keyBytes)}"
}

fun Algorithm.formatMultikey(keyBytes: ByteArray): String {
    val prefixedBytes = didPrefix + keyBytes
    return "$BASE58_MULTIBASE_PREFIX${prefixedBytes.encodeToBase58()}"
}

fun String.parseDidKey(): Pair<EllipticCurveAlgorithm, ByteArray> {
    val multiKey = extractMultikey()
    return multiKey.parseMultiKey()
}

fun String.parseMultiKey(): Pair<EllipticCurveAlgorithm, ByteArray> {
    val prefixedBytes = extractPrefixedBytes()
    val algo = when {
        ES256.prefixes(prefixedBytes) -> ES256
        ES256K.prefixes(prefixedBytes) -> ES256K
        else -> throw IllegalArgumentException("Unsupported key type")
    }
    return algo to algo.removePrefix(prefixedBytes)
}

suspend fun String.verifyDid(data: ByteArray, sig: ByteArray, useLowS: Boolean = false): Boolean {
    return withContext(Dispatchers.Default) {
        val (algo, publicKeyBytes) = parseDidKey()
        return@withContext algo.verify(publicKeyBytes, data, sig, useLowS)
    }
}
