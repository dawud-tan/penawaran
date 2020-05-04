package org.bouncycastle.operator;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class DefaultSignatureAlgorithmIdentifierFinder
        implements SignatureAlgorithmIdentifierFinder {
    public AlgorithmIdentifier find(String sigAlgName) {
        return new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519);
    }
}