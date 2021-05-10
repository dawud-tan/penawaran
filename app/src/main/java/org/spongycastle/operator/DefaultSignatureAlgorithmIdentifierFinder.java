package org.spongycastle.operator;

import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.nist.NISTObjectIdentifiers;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.util.Strings;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class DefaultSignatureAlgorithmIdentifierFinder
        implements SignatureAlgorithmIdentifierFinder {
    private static Map algorithms = new HashMap();
    private static Set noParams = new HashSet();
    private static Set pkcs15RsaEncryption = new HashSet();
    private static Map digestOids = new HashMap();

    static {
        algorithms.put("SHA512WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha512WithRSAEncryption);
        algorithms.put("SHA512WITHRSA", PKCSObjectIdentifiers.sha512WithRSAEncryption);
        //
        // PKCS 1.5 encrypted  algorithms
        //
        pkcs15RsaEncryption.add(PKCSObjectIdentifiers.sha512WithRSAEncryption);
        digestOids.put(PKCSObjectIdentifiers.sha512WithRSAEncryption, NISTObjectIdentifiers.id_sha512);
    }

    private static AlgorithmIdentifier generate(String signatureAlgorithm) {
        AlgorithmIdentifier sigAlgId;

        String algorithmName = Strings.toUpperCase(signatureAlgorithm);
        ASN1ObjectIdentifier sigOID = (ASN1ObjectIdentifier) algorithms.get(algorithmName);
        if (sigOID == null) {
            throw new IllegalArgumentException("Unknown signature type requested: " + algorithmName);
        }

        if (noParams.contains(sigOID)) {
            sigAlgId = new AlgorithmIdentifier(sigOID);
        } else {
            sigAlgId = new AlgorithmIdentifier(sigOID, DERNull.INSTANCE);
        }

        return sigAlgId;
    }

    public AlgorithmIdentifier find(String sigAlgName) {
        return generate(sigAlgName);
    }
}