package com.frybits.atproto.identity

import com.frybits.atproto.common.DidDocument

interface DidCache {

    suspend fun cacheDid(did: String, doc: DidDocument, prevResult: CachedResult?)

    suspend fun checkCache(did: String): CachedResult?

    suspend fun refreshCache(did: String, getDoc: suspend () -> DidDocument?, prevResult: CachedResult?)

    suspend fun clearEntry(did: String)

    suspend fun clear()
}
