package com.frybits.atproto.crypto

import com.frybits.atproto.crypto.utils.formatDidKey
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.interfaces.ECPublicKey

internal class ECDSAKeyPair internal constructor(
    jwtAlg: Algorithm,
    exportable: Boolean,
    override val privateKey: ECPrivateKey,
    override val publicKey: ECPublicKey
): ATKeyPair(jwtAlg, exportable) {

    override val did: String = jwtAlg.formatDidKey(publicKey.q.getEncoded(true))

    override fun export(): ECPrivateKey {
        require(exportable) { "Private key is not exportable" }
        return privateKey
    }
}
