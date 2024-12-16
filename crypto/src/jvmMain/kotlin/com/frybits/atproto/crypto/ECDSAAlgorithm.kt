package com.frybits.atproto.crypto

import com.frybits.atproto.crypto.utils.formatDidKey
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.bouncycastle.jce.spec.ECPublicKeySpec

internal class ECDSAAlgorithm internal constructor(
    jwtAlg: JWTAlgorithm,
    private val privateKey: ECPrivateKey
): Algorithm(jwtAlg) {

    private val publicKey: ECPublicKey = with(jwtAlg) {
        val publicKeyPoint = parameter.g.multiply(privateKey.d)
        val publicKeySpec = ECPublicKeySpec(publicKeyPoint, jwtAlg.parameter)
        return@with keyFactory.generatePublic(publicKeySpec) as ECPublicKey
    }

    override val did: String = jwtAlg.formatDidKey(publicKey.q.getEncoded(true))

    override suspend fun sign(msg: ByteArray): ByteArray {
        return jwtAlg.sign(privateKey, msg)
    }
}
