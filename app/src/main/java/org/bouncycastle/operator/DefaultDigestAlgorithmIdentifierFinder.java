package org.bouncycastle.operator;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.util.HashMap;
import java.util.Map;

public class DefaultDigestAlgorithmIdentifierFinder
        implements DigestAlgorithmIdentifierFinder {
    private static Map digestOids = new HashMap();
    private static Map digestNameToOids = new HashMap();

    static {
        digestNameToOids.put("SHA-512", NISTObjectIdentifiers.id_sha512);
        digestNameToOids.put("SHA512", NISTObjectIdentifiers.id_sha512);
    }

    public AlgorithmIdentifier find(AlgorithmIdentifier sigAlgId) {
        AlgorithmIdentifier digAlgId;
        if (sigAlgId.getAlgorithm().equals(EdECObjectIdentifiers.id_Ed25519)) {
            digAlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512);
        } else {
            digAlgId = new AlgorithmIdentifier((ASN1ObjectIdentifier) digestOids.get(sigAlgId.getAlgorithm()), DERNull.INSTANCE);
        }

        return digAlgId;
    }

}