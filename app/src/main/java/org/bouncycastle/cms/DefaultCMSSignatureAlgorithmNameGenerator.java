package org.bouncycastle.cms;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class DefaultCMSSignatureAlgorithmNameGenerator
        implements CMSSignatureAlgorithmNameGenerator {

    public DefaultCMSSignatureAlgorithmNameGenerator() {
    }

    public String getSignatureName(AlgorithmIdentifier digestAlg, AlgorithmIdentifier encryptionAlg) {
        return "Ed25519";
    }
}