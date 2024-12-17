package com.frybits.atproto.crypto.algorithms

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bouncycastle.crypto.Signer
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey

sealed class EllipticCurveAlgorithm(
    didPrefix: ByteArray,
    keyFactory: KeyFactory,
    keyPairGenerator: KeyPairGenerator,
    parameter: ECNamedCurveParameterSpec,
    signature: Signer
): Algorithm(
    didPrefix = didPrefix,
    keyFactory = keyFactory,
    keyPairGenerator = keyPairGenerator,
    parameter = parameter,
    signature = signature
) {

    suspend fun verify(publicKeyBytes: ByteArray, data: ByteArray, sig: ByteArray, useLowS: Boolean = true): Boolean {
        return withContext(Dispatchers.Default) {
            require(parameter is ECNamedCurveParameterSpec)
            val point = parameter.curve.decodePoint(publicKeyBytes)
            val publicKeySpec = ECPublicKeySpec(point, parameter)
            val publicKey = keyFactory.generatePublic(publicKeySpec)
            return@withContext verify(publicKey, data, sig, useLowS)
        }
    }

    suspend fun verify(publicKey: PublicKey, data: ByteArray, sig: ByteArray, useLowS: Boolean = true): Boolean {
        if (useLowS) {
            require(parameter is ECNamedCurveParameterSpec)
            val s = BigInteger(1, sig, 32, 32)
            if (s > parameter.curve.order.shiftRight(1)) {
                return false
            }
        }
        return super.verify(PublicKeyFactory.createKey(publicKey.encoded), data, sig)
    }

    suspend fun sign(privateKey: PrivateKey, msg: ByteArray, useLowS: Boolean = true): ByteArray {
        val sig = super.sign(PrivateKeyFactory.createKey(privateKey.encoded), msg)
        if (useLowS) {
            require(parameter is ECNamedCurveParameterSpec)
            var s = BigInteger(1, sig, 32, 32)

            if (s > parameter.curve.order.shiftRight(1)) {
                s = parameter.curve.order.subtract(s)
            }

            val sBA = s.toByteArray()
            repeat(32) { i ->
                sig[32 + i] = sBA[i]
            }
        }
        return sig
    }
}
