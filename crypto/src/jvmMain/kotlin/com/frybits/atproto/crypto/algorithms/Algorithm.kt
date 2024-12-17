package com.frybits.atproto.crypto.algorithms

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.Signer
import org.bouncycastle.jcajce.util.BCJcaJceHelper
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.spec.AlgorithmParameterSpec

internal val bCJcaJceHelper = BCJcaJceHelper()

sealed class Algorithm(
    val didPrefix: ByteArray,
    val keyFactory: KeyFactory,
    val keyPairGenerator: KeyPairGenerator,
    val parameter: AlgorithmParameterSpec,
    protected val signature: Signer
) {

    init {
        keyPairGenerator.initialize(parameter)
    }

    protected val mutex = Mutex()

    suspend fun verify(publicKeyParam: CipherParameters, data: ByteArray, sig: ByteArray): Boolean {
        return withContext(Dispatchers.Default) {
            return@withContext mutex.withLock {
                signature.init(false, publicKeyParam)
                signature.update(data, 0, data.size)
                return@withLock signature.verifySignature(sig)
            }
        }
    }

    suspend fun sign(privateKeyParam: CipherParameters, msg: ByteArray): ByteArray {
        return withContext(Dispatchers.Default) {
            return@withContext mutex.withLock {
                signature.init(true, privateKeyParam)
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
