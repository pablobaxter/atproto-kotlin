package com.frybits.atproto.crypto.utils

import com.frybits.atproto.crypto.Algorithm
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.jce.spec.ECPublicKeySpec

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

fun String.parseDidKey(): Pair<Algorithm, ByteArray> {
    val multiKey = extractMultikey()
    return multiKey.parseMultiKey()
}

fun String.parseMultiKey(): Pair<Algorithm, ByteArray> {
    val prefixedBytes = extractPrefixedBytes()
    val algo = requireNotNull(Algorithm.entries.firstOrNull { it.prefixes(prefixedBytes) }) {
        "Unsupported key type"
    }
    return algo to algo.removePrefix(prefixedBytes)
}

suspend fun String.verifyDid(data: ByteArray, sig: ByteArray): Boolean {
    return withContext(Dispatchers.Default) {
        val (algo, publicKeyBytes) = parseDidKey()
        return@withContext algo.verify(publicKeyBytes, data, sig)
    }
}
