package com.frybits.atproto.crypto.p256

import com.frybits.atproto.crypto.KeyPair
import com.frybits.atproto.crypto.P256_JWT_ALG
import org.bouncycastle.jcajce.util.BCJcaJceHelper
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec

class P256KeyPair(
    private val privateKey: ByteArray,
    private val exportable: Boolean
) : KeyPair {

    private val bCJcaJceHelper = BCJcaJceHelper()
    override val jwtAlg: String = P256_JWT_ALG

    private val publicKey = bCJcaJceHelper.createKeyFactory("ECDSA").generatePrivate(PKCS8EncodedKeySpec(privateKey)).generatePublicKey().encoded

    private fun PrivateKey.generatePublicKey(): PublicKey {
        val spec = ECNamedCurveTable.getParameterSpec("secp256r1")
        val pointQ = spec.g.multiply(BigInteger(1, privateKey))
    }
}