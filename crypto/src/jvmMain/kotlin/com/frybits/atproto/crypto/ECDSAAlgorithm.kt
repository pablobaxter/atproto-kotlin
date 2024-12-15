package com.frybits.atproto.crypto

import com.frybits.atproto.crypto.utils.BASE58_MULTIBASE_PREFIX
import com.frybits.atproto.crypto.utils.DID_KEY_PREFIX
import com.frybits.atproto.crypto.utils.encodeToBase58
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.interfaces.ECPublicKey

internal class ECDSAAlgorithm internal constructor(
    name: String,
    override val jwtAlg: String,
    private val prefix: ByteArray,
    private val privateKey: ECPrivateKey?,
    private val publicKey: ECPublicKey
): Algorithm(name) {

    private val key = (prefix + publicKey.q.getEncoded(true)).encodeToBase58()

    override val did: String = "$DID_KEY_PREFIX$BASE58_MULTIBASE_PREFIX$key"

    override suspend fun sign(msg: ByteArray): ByteArray {
        TODO("Not yet implemented")
    }

    override suspend fun verify(pubDid: String, data: ByteArray, sig: ByteArray): Boolean {
        TODO("Not yet implemented")
    }
}