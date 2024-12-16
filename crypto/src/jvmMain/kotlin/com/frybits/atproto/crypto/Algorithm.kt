package com.frybits.atproto.crypto

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.bouncycastle.jcajce.util.BCJcaJceHelper
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException
import java.security.spec.AlgorithmParameterSpec

private val bCJcaJceHelper = BCJcaJceHelper()

enum class Algorithm(
    val didPrefix: ByteArray,
    val parameter: AlgorithmParameterSpec,
    val keyFactory: KeyFactory,
    val keyPairGenerator: KeyPairGenerator,
    private val signature: Signature
) {
    ES256(
        byteArrayOf(0x80.toByte(), 0x24),
        ECNamedCurveTable.getParameterSpec("secp256r1"),
        bCJcaJceHelper.createKeyFactory("ECDSA"),
        bCJcaJceHelper.createKeyPairGenerator("ECDSA"),
        bCJcaJceHelper.createSignature("SHA256withECDSA")
    ),
    ES256K(
        byteArrayOf(0xE7.toByte(), 0x01),
        ECNamedCurveTable.getParameterSpec("secp256k1"),
        bCJcaJceHelper.createKeyFactory("ECDSA"),
        bCJcaJceHelper.createKeyPairGenerator("ECDSA"),
        bCJcaJceHelper.createSignature("SHA256withECDSA")
    );

    private val mutex = Mutex()

    init {
        keyPairGenerator.initialize(parameter)
    }

    internal suspend fun sign(privateKey: PrivateKey, msg: ByteArray): ByteArray {
        return withContext(Dispatchers.Default) {
            return@withContext mutex.withLock {
                signature.initSign(privateKey)
                signature.update(msg)
                return@withLock signature.sign()
            }
        }
    }

    internal suspend fun verify(publicKeyBytes: ByteArray, data: ByteArray, sig: ByteArray): Boolean {
        return withContext(Dispatchers.Default) {
            require(parameter is ECNamedCurveParameterSpec)
            val point = parameter.curve.decodePoint(publicKeyBytes)
            val publicKeySpec = ECPublicKeySpec(point, parameter)
            val publicKey = keyFactory.generatePublic(publicKeySpec)
            return@withContext verify(publicKey, data, sig)
        }
    }

    internal suspend fun verify(publicKey: PublicKey, data: ByteArray, sig: ByteArray): Boolean {
        return withContext(Dispatchers.Default) {
            return@withContext mutex.withLock {
                signature.initVerify(publicKey)
                signature.update(data)
                return@withLock signature.verify(sig)
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
