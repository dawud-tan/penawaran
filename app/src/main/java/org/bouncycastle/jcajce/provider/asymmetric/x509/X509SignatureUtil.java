package org.bouncycastle.jcajce.provider.asymmetric.x509;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PSSParameterSpec;
import java.util.HashMap;
import java.util.Map;

class X509SignatureUtil {
    private static final Map<ASN1ObjectIdentifier, String> algNames = new HashMap<ASN1ObjectIdentifier, String>();

    static {
        algNames.put(EdECObjectIdentifiers.id_Ed25519, "Ed25519");
    }

    private static final ASN1Null derNull = DERNull.INSTANCE;

    static void setSignatureParameters(
            Signature signature,
            ASN1Encodable params)
            throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        if (params != null && !derNull.equals(params)) {
            AlgorithmParameters sigParams = AlgorithmParameters.getInstance(signature.getAlgorithm(), signature.getProvider());

            try {
                sigParams.init(params.toASN1Primitive().getEncoded());
            } catch (IOException e) {
                throw new SignatureException("IOException decoding parameters: " + e.getMessage());
            }

            if (signature.getAlgorithm().endsWith("MGF1")) {
                try {
                    signature.setParameter(sigParams.getParameterSpec(PSSParameterSpec.class));
                } catch (GeneralSecurityException e) {
                    throw new SignatureException("Exception extracting parameters: " + e.getMessage());
                }
            }
        }
    }

    static String getSignatureName(
            AlgorithmIdentifier sigAlgId) {
        // deal with the "weird" ones.
        String algName = algNames.get(sigAlgId.getAlgorithm());
        if (algName != null) {
            return algName;
        }

        return findAlgName(sigAlgId.getAlgorithm());
    }

    private static String findAlgName(ASN1ObjectIdentifier algOid) {
        Provider prov = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);

        if (prov != null) {
            String algName = lookupAlg(prov, algOid);
            if (algName != null) {
                return algName;
            }
        }

        Provider[] provs = Security.getProviders();

        for (int i = 0; i != provs.length; i++) {
            if (prov != provs[i]) {
                String algName = lookupAlg(provs[i], algOid);
                if (algName != null) {
                    return algName;
                }
            }
        }

        return algOid.getId();
    }

    private static String lookupAlg(Provider prov, ASN1ObjectIdentifier algOid) {
        String algName = prov.getProperty("Alg.Alias.Signature." + algOid);

        if (algName != null) {
            return algName;
        }

        algName = prov.getProperty("Alg.Alias.Signature.OID." + algOid);

        return algName;
    }
}