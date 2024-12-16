package com.frybits.atproto.crypto

import com.frybits.atproto.crypto.utils.parseDidKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.bouncycastle.jcajce.util.BCJcaJceHelper
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature

private val bCJcaJceHelper = BCJcaJceHelper()

enum class JWTAlgorithm(
    val didPrefix: ByteArray,
    val parameter: ECNamedCurveParameterSpec,
    val keyFactory: KeyFactory,
    private val signature: Signature
) {
    ES256(
        byteArrayOf(0x80.toByte(), 0x24),
        ECNamedCurveTable.getParameterSpec("secp256r1"),
        bCJcaJceHelper.createKeyFactory("ECDSA"),
        bCJcaJceHelper.createSignature("SHA256withECDSA")
    ),
    ES256K(
        byteArrayOf(0xE7.toByte(), 0x01),
        ECNamedCurveTable.getParameterSpec("secp256k1"),
        bCJcaJceHelper.createKeyFactory("ECDSA"),
        bCJcaJceHelper.createSignature("SHA256withECDSA")
    );

    private val mutex = Mutex()

    internal suspend fun sign(privateKey: PrivateKey, msg: ByteArray): ByteArray {
        return withContext(Dispatchers.Default) {
            return@withContext mutex.withLock {
                signature.initSign(privateKey)
                signature.update(msg)
                return@withLock signature.sign()
            }
        }
    }

    suspend fun verify(pubDid: String, data: ByteArray, sig: ByteArray): Boolean {
        return withContext(Dispatchers.Default) {
            val (algo, publicKeyBytes) = pubDid.parseDidKey()
            val point = algo.parameter.curve.decodePoint(publicKeyBytes)
            val publicKeySpec = ECPublicKeySpec(point, algo.parameter)
            val publicKey = algo.keyFactory.generatePublic(publicKeySpec)
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
