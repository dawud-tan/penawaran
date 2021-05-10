package org.spongycastle.operator;

import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class GenericKey {
    private AlgorithmIdentifier algorithmIdentifier;
    private Object representation;

    /**
     * @param representation key data
     * @deprecated provide an AlgorithmIdentifier.
     */
    public GenericKey(Object representation) {
        this.algorithmIdentifier = null;
        this.representation = representation;
    }

}
