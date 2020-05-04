package org.bouncycastle.jcajce.provider.asymmetric;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

import java.util.HashMap;
import java.util.Map;

public class EdEC {
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".edec.";

    private static final Map<String, String> edxAttributes = new HashMap<String, String>();

    static {
        edxAttributes.put("SupportedKeyClasses", "java.security.interfaces.ECPublicKey|java.security.interfaces.ECPrivateKey");
        edxAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    public static class Mappings
            extends AsymmetricAlgorithmProvider {
        public Mappings() {
        }

        public void configure(ConfigurableProvider provider) {

            provider.addAlgorithm("KeyFactory.ED25519", PREFIX + "KeyFactorySpi$Ed25519");

            provider.addAlgorithm("Signature.ED25519", PREFIX + "SignatureSpi$Ed25519");
            provider.addAlgorithm("Alg.Alias.Signature", EdECObjectIdentifiers.id_Ed25519, "ED25519");

            registerOid(provider, EdECObjectIdentifiers.id_Ed25519, "EDDSA", new KeyFactorySpi.Ed25519());
        }
    }
}