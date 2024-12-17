package com.frybits.atproto.crypto

import com.frybits.atproto.crypto.algorithms.EllipticCurveAlgorithm
import com.frybits.atproto.crypto.utils.formatDidKey
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPrivateKeySpec

internal class ECDSAKeyPair internal constructor(
    override val jwtAlg: EllipticCurveAlgorithm,
    exportable: Boolean,
    override val privateKeyParam: ECPrivateKeyParameters,
    override val publicKeyParam: ECPublicKeyParameters
): ATKeyPair(exportable) {

    override val did: String = jwtAlg.formatDidKey(publicKeyParam.q.getEncoded(true))

    override fun export(): ECPrivateKey {
        require(exportable) { "Private key is not exportable" }
        val privateKeySpec = ECPrivateKeySpec(privateKeyParam.d, jwtAlg.parameter as ECParameterSpec)
        return jwtAlg.keyFactory.generatePrivate(privateKeySpec) as ECPrivateKey
    }
}
