package org.spongycastle.operator;

import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.nist.NISTObjectIdentifiers;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

import java.util.HashMap;
import java.util.Map;

public class DefaultDigestAlgorithmIdentifierFinder
        implements DigestAlgorithmIdentifierFinder {
    private static Map digestOids = new HashMap();
    private static Map digestNameToOids = new HashMap();

    static {
        //
        // digests
        //
        digestOids.put(PKCSObjectIdentifiers.sha512WithRSAEncryption, NISTObjectIdentifiers.id_sha512);
        digestNameToOids.put("SHA-512", NISTObjectIdentifiers.id_sha512);
        digestNameToOids.put("SHA512", NISTObjectIdentifiers.id_sha512);
    }

    public AlgorithmIdentifier find(AlgorithmIdentifier sigAlgId) {
        AlgorithmIdentifier digAlgId;
        digAlgId = new AlgorithmIdentifier((ASN1ObjectIdentifier) digestOids.get(sigAlgId.getAlgorithm()), DERNull.INSTANCE);
        return digAlgId;
    }

    public AlgorithmIdentifier find(String digAlgName) {
        return new AlgorithmIdentifier((ASN1ObjectIdentifier) digestNameToOids.get(digAlgName), DERNull.INSTANCE);
    }
}