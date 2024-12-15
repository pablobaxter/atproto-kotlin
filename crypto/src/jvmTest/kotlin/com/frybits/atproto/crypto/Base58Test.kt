package com.frybits.atproto.crypto

import com.frybits.atproto.crypto.utils.decodeBase58
import com.frybits.atproto.crypto.utils.encodeToBase58
import kotlin.test.Test
import kotlin.test.assertEquals

class Base58Test {

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun `base58 encode-decode test`() {
        val helloWorld = "Hello World!" to "2NEpo7TZRRrLZSi2U"
        assertEquals(helloWorld.second, helloWorld.first.toByteArray().encodeToBase58())
        assertEquals(helloWorld.first, helloWorld.second.decodeBase58().toString(Charsets.UTF_8))

        val allLetters = "The quick brown fox jumps over the lazy dog." to "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z"
        assertEquals(allLetters.second, allLetters.first.toByteArray().encodeToBase58())
        assertEquals(allLetters.first, allLetters.second.decodeBase58().toString(Charsets.UTF_8))

        val hex = "0000287fb4cd" to "11233QC4"
        assertEquals(hex.second, hex.first.hexToByteArray().encodeToBase58())
        assertEquals(hex.first, hex.second.decodeBase58().toHexString())
    }
}