package com.frybits.atproto.crypto

import com.frybits.atproto.crypto.utils.decodeBase58
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.math.BigInteger
import java.security.PrivateKey
import java.security.PublicKey

sealed class ATKeyPair(
    val jwtAlg: Algorithm,
    protected val exportable: Boolean
) {

    abstract val privateKey: PrivateKey
    abstract val publicKey: PublicKey
    abstract val did: String

    suspend fun sign(msg: ByteArray): ByteArray {
        return jwtAlg.sign(privateKey, msg)
    }

    suspend fun verify(data: ByteArray, sig: ByteArray): Boolean {
        return jwtAlg.verify(publicKey, data, sig)
    }

    abstract fun export(): PrivateKey
}

suspend fun P256KeyPair(exportable: Boolean = false): ATKeyPair {
    return ECDSAKeyPair(Algorithm.ES256, exportable)
}

suspend fun P256KeyPair(privateKey: String, exportable: Boolean = false): ATKeyPair {
    return P256KeyPair(privateKey.decodeBase58(), exportable)
}

suspend fun P256KeyPair(privateKey: ByteArray, exportable: Boolean = false): ATKeyPair {
    return ECDSAKeyPair(Algorithm.ES256, privateKey, exportable)
}

suspend fun P256KeyPair(privateKey: PrivateKey, exportable: Boolean = false): ATKeyPair {
    require(privateKey is ECPrivateKey) { "Private key must be of type ${ECPrivateKey::class.java.name}" }
    return ECDSAKeyPair(Algorithm.ES256, privateKey, exportable)
}

suspend fun K256KeyPair(exportable: Boolean = false): ATKeyPair {
    return ECDSAKeyPair(Algorithm.ES256K, exportable)
}

@OptIn(ExperimentalStdlibApi::class)
suspend fun K256KeyPair(privateKey: String, exportable: Boolean = false): ATKeyPair {
    return K256KeyPair(privateKey.hexToByteArray(), exportable)
}

suspend fun K256KeyPair(privateKey: ByteArray, exportable: Boolean = false): ATKeyPair {
    return ECDSAKeyPair(Algorithm.ES256K, privateKey, exportable)
}

suspend fun K256KeyPair(privateKey: PrivateKey, exportable: Boolean = false): ATKeyPair {
    require(privateKey is ECPrivateKey) { "Private key must be of type ${ECPrivateKey::class.java.name}" }
    return ECDSAKeyPair(Algorithm.ES256K, privateKey, exportable)
}

private suspend fun ECDSAKeyPair(jwtAlg: Algorithm, privateKeyArray: ByteArray, exportable: Boolean): ATKeyPair {
    return withContext(Dispatchers.Default) {
        val d = BigInteger(1, privateKeyArray)

        require(jwtAlg.parameter is ECNamedCurveParameterSpec)

        val curveSpec = ECParameterSpec(
            jwtAlg.parameter.curve,
            jwtAlg.parameter.g,
            jwtAlg.parameter.n,
            jwtAlg.parameter.h
        )
        val privateKeySpec = ECPrivateKeySpec(d, curveSpec)
        val privateKey = jwtAlg.keyFactory.generatePrivate(privateKeySpec) as ECPrivateKey
        return@withContext ECDSAKeyPair(jwtAlg, privateKey, exportable)
    }
}

private suspend fun ECDSAKeyPair(jwtAlg: Algorithm, privateKey: ECPrivateKey, exportable: Boolean): ATKeyPair {
    return withContext(Dispatchers.Default) {
        require(jwtAlg.parameter is ECNamedCurveParameterSpec)
        val publicKeyPoint = jwtAlg.parameter.g.multiply(privateKey.d)
        val publicKeySpec = ECPublicKeySpec(publicKeyPoint, jwtAlg.parameter)
        val publicKey = jwtAlg.keyFactory.generatePublic(publicKeySpec) as ECPublicKey

        return@withContext ECDSAKeyPair(jwtAlg, exportable, privateKey, publicKey)
    }
}

private suspend fun ECDSAKeyPair(jwtAlg: Algorithm, exportable: Boolean): ATKeyPair {
    return withContext(Dispatchers.Default) {
        val keyPair = jwtAlg.keyPairGenerator.generateKeyPair()
        return@withContext ECDSAKeyPair(
            jwtAlg,
            exportable,
            keyPair.private as ECPrivateKey,
            keyPair.public as ECPublicKey
        )
    }
}
