package com.frybits.atproto.crypto.utils

import com.frybits.atproto.crypto.JWTAlgorithm

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

fun JWTAlgorithm.formatDidKey(keyBytes: ByteArray): String {
    return "$DID_KEY_PREFIX${formatMultikey(keyBytes)}"
}

fun JWTAlgorithm.formatMultikey(keyBytes: ByteArray): String {
    val prefixedBytes = didPrefix + keyBytes
    return "$BASE58_MULTIBASE_PREFIX${prefixedBytes.encodeToBase58()}"
}

fun String.parseDidKey(): Pair<JWTAlgorithm, ByteArray> {
    val multiKey = extractMultikey()
    return multiKey.parseMultiKey()
}

fun String.parseMultiKey(): Pair<JWTAlgorithm, ByteArray> {
    val prefixedBytes = extractPrefixedBytes()
    val algo = JWTAlgorithm.entries.first { it.prefixes(prefixedBytes) }
    return algo to algo.removePrefix(prefixedBytes)
}
