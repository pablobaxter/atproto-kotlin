package com.frybits.atproto.crypto

import com.frybits.atproto.crypto.algorithms.Algorithm
import com.frybits.atproto.crypto.algorithms.ES256
import com.frybits.atproto.crypto.algorithms.ES256K
import com.frybits.atproto.crypto.algorithms.EllipticCurveAlgorithm
import com.frybits.atproto.crypto.utils.decodeBase58
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import java.math.BigInteger
import java.security.PrivateKey

sealed class ATKeyPair(
    protected val exportable: Boolean
) {

    abstract val jwtAlg: Algorithm
    abstract val privateKeyParam: CipherParameters
    abstract val publicKeyParam: CipherParameters
    abstract val did: String

    suspend fun sign(msg: ByteArray): ByteArray {
        return jwtAlg.sign(privateKeyParam, msg)
    }

    suspend fun verify(data: ByteArray, sig: ByteArray): Boolean {
        return jwtAlg.verify(publicKeyParam, data, sig)
    }

    abstract fun export(): PrivateKey
}

suspend fun P256KeyPair(exportable: Boolean = false): ATKeyPair {
    return ECDSAKeyPair(ES256, exportable)
}

suspend fun P256KeyPair(privateKey: String, exportable: Boolean = false): ATKeyPair {
    return P256KeyPair(privateKey.decodeBase58(), exportable)
}

suspend fun P256KeyPair(privateKey: ByteArray, exportable: Boolean = false): ATKeyPair {
    return ECDSAKeyPair(ES256, privateKey, exportable)
}

suspend fun P256KeyPair(privateKey: PrivateKey, exportable: Boolean = false): ATKeyPair {
    require(privateKey is ECPrivateKey) { "Private key must be of type ${ECPrivateKey::class.java.name}" }
    return ECDSAKeyPair(ES256, PrivateKeyFactory.createKey(privateKey.encoded) as ECPrivateKeyParameters, exportable)
}

suspend fun K256KeyPair(exportable: Boolean = false): ATKeyPair {
    return ECDSAKeyPair(ES256K, exportable)
}

@OptIn(ExperimentalStdlibApi::class)
suspend fun K256KeyPair(privateKey: String, exportable: Boolean = false): ATKeyPair {
    return K256KeyPair(privateKey.hexToByteArray(), exportable)
}

suspend fun K256KeyPair(privateKey: ByteArray, exportable: Boolean = false): ATKeyPair {
    return ECDSAKeyPair(ES256K, privateKey, exportable)
}

suspend fun K256KeyPair(privateKey: PrivateKey, exportable: Boolean = false): ATKeyPair {
    require(privateKey is ECPrivateKey) { "Private key must be of type ${ECPrivateKey::class.java.name}" }
    return ECDSAKeyPair(ES256K, PrivateKeyFactory.createKey(privateKey.encoded) as ECPrivateKeyParameters, exportable)
}

private suspend fun ECDSAKeyPair(jwtAlg: EllipticCurveAlgorithm, privateKeyArray: ByteArray, exportable: Boolean): ATKeyPair {
    return withContext(Dispatchers.Default) {
        val d = BigInteger(1, privateKeyArray)
        require(jwtAlg.parameter is ECNamedCurveParameterSpec)

        val privateKeyParam = ECPrivateKeyParameters(
            d,
            ECDomainParameters(jwtAlg.parameter.curve, jwtAlg.parameter.g, jwtAlg.parameter.n, jwtAlg.parameter.h)
        )

        return@withContext ECDSAKeyPair(jwtAlg, privateKeyParam, exportable)
    }
}

private suspend fun ECDSAKeyPair(jwtAlg: EllipticCurveAlgorithm, privateKeyParam: ECPrivateKeyParameters, exportable: Boolean): ATKeyPair {
    return withContext(Dispatchers.Default) {
        val domainParams = privateKeyParam.parameters
        val publicKeyPoint = domainParams.g.multiply(privateKeyParam.d)
        val publicKeyParam = ECPublicKeyParameters(publicKeyPoint, domainParams)

        return@withContext ECDSAKeyPair(
            jwtAlg,
            exportable,
            privateKeyParam,
            publicKeyParam
        )
    }
}

private suspend fun ECDSAKeyPair(jwtAlg: EllipticCurveAlgorithm, exportable: Boolean): ATKeyPair {
    return withContext(Dispatchers.Default) {
        val keyPair = jwtAlg.keyPairGenerator.generateKeyPair()
        return@withContext ECDSAKeyPair(
            jwtAlg,
            exportable,
            PrivateKeyFactory.createKey(keyPair.private.encoded) as ECPrivateKeyParameters,
            PublicKeyFactory.createKey(keyPair.public.encoded) as ECPublicKeyParameters
        )
    }
}
