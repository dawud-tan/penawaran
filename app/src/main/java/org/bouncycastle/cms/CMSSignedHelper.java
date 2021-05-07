package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.util.HashMap;
import java.util.Map;

class CMSSignedHelper {
    static final CMSSignedHelper INSTANCE = new CMSSignedHelper();

    private static final Map encryptionAlgs = new HashMap();

    private static void addEntries(ASN1ObjectIdentifier alias, String encryption) {
        encryptionAlgs.put(alias.getId(), encryption);
    }

    static {
        addEntries(PKCSObjectIdentifiers.sha512WithRSAEncryption, "RSA");
    }


    /**
     * Return the digest encryption algorithm using one of the standard
     * JCA string representations rather the the algorithm identifier (if
     * possible).
     */
    String getEncryptionAlgName(
            String encryptionAlgOID) {
        String algName = (String) encryptionAlgs.get(encryptionAlgOID);

        if (algName != null) {
            return algName;
        }

        return encryptionAlgOID;
    }

    AlgorithmIdentifier fixAlgID(AlgorithmIdentifier algId) {
        if (algId.getParameters() == null) {
            return new AlgorithmIdentifier(algId.getAlgorithm(), DERNull.INSTANCE);
        }

        return algId;
    }

}