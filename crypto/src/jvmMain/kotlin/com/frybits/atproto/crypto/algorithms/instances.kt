package com.frybits.atproto.crypto.algorithms

import org.bouncycastle.crypto.signers.DSADigestSigner
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.PlainDSAEncoding
import org.bouncycastle.crypto.signers.StandardDSAEncoding
import org.bouncycastle.crypto.util.DigestFactory
import org.bouncycastle.jce.ECNamedCurveTable

object ES256: EllipticCurveAlgorithm(
    didPrefix = byteArrayOf(0x80.toByte(), 0x24),
    parameter = ECNamedCurveTable.getParameterSpec("secp256r1"),
    keyFactory = bCJcaJceHelper.createKeyFactory("ECDSA"),
    keyPairGenerator = bCJcaJceHelper.createKeyPairGenerator("ECDSA"),
    signature = DSADigestSigner(ECDSASigner(), DigestFactory.createSHA256(), PlainDSAEncoding.INSTANCE)
)

object ES256WithDer: EllipticCurveAlgorithm(
    didPrefix = byteArrayOf(0x80.toByte(), 0x24),
    parameter = ECNamedCurveTable.getParameterSpec("secp256r1"),
    keyFactory = bCJcaJceHelper.createKeyFactory("ECDSA"),
    keyPairGenerator = bCJcaJceHelper.createKeyPairGenerator("ECDSA"),
    signature = DSADigestSigner(ECDSASigner(), DigestFactory.createSHA256(), StandardDSAEncoding.INSTANCE)
)

object ES256K: EllipticCurveAlgorithm(
    didPrefix = byteArrayOf(0xE7.toByte(), 0x01),
    parameter = ECNamedCurveTable.getParameterSpec("secp256k1"),
    keyFactory = bCJcaJceHelper.createKeyFactory("ECDSA"),
    keyPairGenerator = bCJcaJceHelper.createKeyPairGenerator("ECDSA"),
    signature = DSADigestSigner(ECDSASigner(), DigestFactory.createSHA256(), PlainDSAEncoding.INSTANCE)
)

object ES256KWithDer: EllipticCurveAlgorithm(
    didPrefix = byteArrayOf(0xE7.toByte(), 0x01),
    parameter = ECNamedCurveTable.getParameterSpec("secp256k1"),
    keyFactory = bCJcaJceHelper.createKeyFactory("ECDSA"),
    keyPairGenerator = bCJcaJceHelper.createKeyPairGenerator("ECDSA"),
    signature = DSADigestSigner(ECDSASigner(), DigestFactory.createSHA256(), StandardDSAEncoding.INSTANCE)
)
