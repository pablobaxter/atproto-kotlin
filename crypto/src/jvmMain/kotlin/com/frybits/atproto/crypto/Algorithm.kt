package com.frybits.atproto.crypto

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.bouncycastle.crypto.Signer
import org.bouncycastle.crypto.signers.DSADigestSigner
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.PlainDSAEncoding
import org.bouncycastle.crypto.util.DigestFactory
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.jcajce.util.BCJcaJceHelper
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.AlgorithmParameterSpec

private val bCJcaJceHelper = BCJcaJceHelper()

enum class Algorithm(
    val didPrefix: ByteArray,
    val parameter: AlgorithmParameterSpec,
    val keyFactory: KeyFactory,
    val keyPairGenerator: KeyPairGenerator,
    protected val signature: Signer
) {

    ES256(
        byteArrayOf(0x80.toByte(), 0x24),
        ECNamedCurveTable.getParameterSpec("secp256r1"),
        bCJcaJceHelper.createKeyFactory("ECDSA"),
        bCJcaJceHelper.createKeyPairGenerator("ECDSA"),
        DSADigestSigner(ECDSASigner(), DigestFactory.createSHA256(), PlainDSAEncoding.INSTANCE)
    ) {

        override suspend fun verify(publicKeyBytes: ByteArray, data: ByteArray, sig: ByteArray): Boolean {
            return verify(publicKeyBytes, data, sig, true)
        }

        suspend fun verify(publicKeyBytes: ByteArray, data: ByteArray, sig: ByteArray, useLowS: Boolean): Boolean {
            return withContext(Dispatchers.Default) {
                require(parameter is ECNamedCurveParameterSpec)
                val point = parameter.curve.decodePoint(publicKeyBytes)
                val publicKeySpec = ECPublicKeySpec(point, parameter)
                val publicKey = keyFactory.generatePublic(publicKeySpec)
                return@withContext verify(publicKey, data, sig, useLowS)
            }
        }

        override suspend fun verify(publicKey: PublicKey, data: ByteArray, sig: ByteArray): Boolean {
            return verify(publicKey, data, sig, true)
        }

        suspend fun verify(publicKey: PublicKey, data: ByteArray, sig: ByteArray, useLowS: Boolean): Boolean {
            if (useLowS) {
                require(parameter is ECNamedCurveParameterSpec)
                val s = BigInteger(1, sig, 32, 32)
                if (s > parameter.curve.order.shiftRight(1)) {
                    return false
                }
            }
            return super.verify(publicKey, data, sig)
        }
    },

    ES256K(
        byteArrayOf(0xE7.toByte(), 0x01),
        ECNamedCurveTable.getParameterSpec("secp256k1"),
        bCJcaJceHelper.createKeyFactory("ECDSA"),
        bCJcaJceHelper.createKeyPairGenerator("ECDSA"),
        DSADigestSigner(ECDSASigner(), DigestFactory.createSHA256(), PlainDSAEncoding.INSTANCE)
    ) {

        override suspend fun verify(publicKeyBytes: ByteArray, data: ByteArray, sig: ByteArray): Boolean {
            return verify(publicKeyBytes, data, sig, true)
        }

        suspend fun verify(publicKeyBytes: ByteArray, data: ByteArray, sig: ByteArray, useLowS: Boolean): Boolean {
            return withContext(Dispatchers.Default) {
                require(parameter is ECNamedCurveParameterSpec)
                val point = parameter.curve.decodePoint(publicKeyBytes)
                val publicKeySpec = ECPublicKeySpec(point, parameter)
                val publicKey = keyFactory.generatePublic(publicKeySpec)
                return@withContext verify(publicKey, data, sig, useLowS)
            }
        }

        override suspend fun verify(publicKey: PublicKey, data: ByteArray, sig: ByteArray): Boolean {
            return verify(publicKey, data, sig, true)
        }

        suspend fun verify(publicKey: PublicKey, data: ByteArray, sig: ByteArray, useLowS: Boolean): Boolean {
            if (useLowS) {
                require(parameter is ECNamedCurveParameterSpec)
                val s = BigInteger(1, sig, 32, 32)
                if (s > parameter.curve.order.shiftRight(1)) {
                    return false
                }
            }
            return super.verify(publicKey, data, sig)
        }

        override suspend fun sign(privateKey: PrivateKey, msg: ByteArray): ByteArray {
            return sign(privateKey, msg, true)
        }

        suspend fun sign(privateKey: PrivateKey, msg: ByteArray, useLowS: Boolean): ByteArray {
            val sig = super.sign(privateKey, msg)
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
    };

    protected val mutex = Mutex()

    init {
        keyPairGenerator.initialize(parameter)
    }

    abstract suspend fun verify(publicKeyBytes: ByteArray, data: ByteArray, sig: ByteArray): Boolean

    open suspend fun verify(publicKey: PublicKey, data: ByteArray, sig: ByteArray): Boolean {
        return withContext(Dispatchers.Default) {
            return@withContext mutex.withLock {
                signature.init(false, PublicKeyFactory.createKey(publicKey.encoded))
                signature.update(data, 0, data.size)
                return@withLock signature.verifySignature(sig)
            }
        }
    }

    open suspend fun sign(privateKey: PrivateKey, msg: ByteArray): ByteArray {
        return withContext(Dispatchers.Default) {
            return@withContext mutex.withLock {
                signature.init(true, PrivateKeyFactory.createKey(privateKey.encoded))
                signature.update(msg, 0, msg.size)
                return@withLock signature.generateSignature()
            }
        }
    }

    internal fun prefixes(keyBytes: ByteArray): Boolean {
        return didPrefix.contentEquals(keyBytes.copyOf(didPrefix.size))
    }

    internal fun removePrefix(keyBytes: ByteArray): ByteArray {
        return keyBytes.copyOfRange(didPrefix.size, keyBytes.size)
    }
}
