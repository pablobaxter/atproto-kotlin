package com.frybits.atproto.crypto

import com.frybits.atproto.crypto.utils.P256_DID_PREFIX
import com.frybits.atproto.crypto.utils.P256_JWT_ALG
import com.frybits.atproto.crypto.utils.SECP256K1_DID_PREFIX
import com.frybits.atproto.crypto.utils.SECP256K1_JWT_ALG
import com.frybits.atproto.crypto.utils.decodeBase58
import org.bouncycastle.jcajce.util.BCJcaJceHelper
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.math.BigInteger

sealed class Algorithm(
    val name: String
) : Didable, Signer, Verifier

private val bCJcaJceHelper = BCJcaJceHelper()

fun P256Algorithm(privateKey: String): Algorithm {
    return P256Algorithm(privateKey.decodeBase58())
}

fun P256Algorithm(privateKey: ByteArray): Algorithm {
    return ECDSAAlgorithm("p256", P256_JWT_ALG, P256_DID_PREFIX, privateKey, ECNamedCurveTable.getParameterSpec("secp256r1"))
}

@OptIn(ExperimentalStdlibApi::class)
fun K256Algorithm(privateKey: String): Algorithm {
    return K256Algorithm(privateKey.hexToByteArray())
}

fun K256Algorithm(privateKey: ByteArray): Algorithm {
    return ECDSAAlgorithm("k256", SECP256K1_JWT_ALG, SECP256K1_DID_PREFIX, privateKey, ECNamedCurveTable.getParameterSpec("secp256k1"))
}

private fun ECDSAAlgorithm(name: String, jwtAlgo: String, prefix: ByteArray, privateKey: ByteArray, parameter: ECNamedCurveParameterSpec): Algorithm {
    val d = BigInteger(1, privateKey)
    val curveSpec = ECParameterSpec(parameter.curve, parameter.g, parameter.n, parameter.h)
    val privateKeySpec = ECPrivateKeySpec(d, curveSpec)
    val keyFactory = bCJcaJceHelper.createKeyFactory("EC")
    val privateKey = keyFactory.generatePrivate(privateKeySpec) as ECPrivateKey

    val publicKeyPoint = parameter.g.multiply(d)
    val publicKeySpec = ECPublicKeySpec(publicKeyPoint, parameter)

    val publicKey = keyFactory.generatePublic(publicKeySpec) as ECPublicKey

    return ECDSAAlgorithm(name, jwtAlgo, prefix, privateKey, publicKey)
}