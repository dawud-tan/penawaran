package org.spongycastle.cms;

import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class DefaultCMSSignatureEncryptionAlgorithmFinder
        implements CMSSignatureEncryptionAlgorithmFinder {

    public AlgorithmIdentifier findEncryptionAlgorithm(AlgorithmIdentifier signatureAlgorithm) {
        return signatureAlgorithm;
    }
}