package com.frybits.atproto.crypto

import com.frybits.atproto.crypto.utils.decodeBase58
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import java.math.BigInteger

sealed class Algorithm(
    override val jwtAlg: JWTAlgorithm
) : Signer {

    abstract val did: String
}

suspend fun P256Algorithm(privateKey: String): Algorithm {
    return P256Algorithm(privateKey.decodeBase58())
}

suspend fun P256Algorithm(privateKey: ByteArray): Algorithm {
    return ECDSAAlgorithm(JWTAlgorithm.ES256, privateKey)
}

@OptIn(ExperimentalStdlibApi::class)
suspend fun K256Algorithm(privateKey: String): Algorithm {
    return K256Algorithm(privateKey.hexToByteArray())
}

suspend fun K256Algorithm(privateKey: ByteArray): Algorithm {
    return ECDSAAlgorithm(JWTAlgorithm.ES256K, privateKey)
}

private suspend fun ECDSAAlgorithm(jwtAlgo: JWTAlgorithm, privateKeyArray: ByteArray): Algorithm {
    return withContext(Dispatchers.Default) {
        val d = BigInteger(1, privateKeyArray)

        val curveSpec = ECParameterSpec(
            jwtAlgo.parameter.curve,
            jwtAlgo.parameter.g,
            jwtAlgo.parameter.n,
            jwtAlgo.parameter.h
        )
        val privateKeySpec = ECPrivateKeySpec(d, curveSpec)
        val privateKey = jwtAlgo.keyFactory.generatePrivate(privateKeySpec) as ECPrivateKey

        return@withContext ECDSAAlgorithm(jwtAlgo, privateKey)
    }
}
