package org.bouncycastle.jcajce.provider.config;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

/**
 * Implemented by the BC provider. This allows setting of hidden parameters,
 * such as the ImplicitCA parameters from X.962, if used.
 */
public interface ConfigurableProvider {

    void addAlgorithm(String key, String value);

    void addAlgorithm(String type, ASN1ObjectIdentifier oid, String className);


    void addKeyInfoConverter(ASN1ObjectIdentifier oid, AsymmetricKeyInfoConverter keyInfoConverter);

}
