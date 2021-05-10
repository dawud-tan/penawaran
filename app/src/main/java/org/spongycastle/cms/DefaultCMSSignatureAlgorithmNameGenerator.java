package org.spongycastle.cms;

import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.nist.NISTObjectIdentifiers;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

import java.util.HashMap;
import java.util.Map;

public class DefaultCMSSignatureAlgorithmNameGenerator
        implements CMSSignatureAlgorithmNameGenerator {
    private final Map encryptionAlgs = new HashMap();
    private final Map digestAlgs = new HashMap();

    private void addEntries(ASN1ObjectIdentifier alias, String digest, String encryption) {
        digestAlgs.put(alias, digest);
        encryptionAlgs.put(alias, encryption);
    }

    public DefaultCMSSignatureAlgorithmNameGenerator() {
        addEntries(PKCSObjectIdentifiers.sha512WithRSAEncryption, "SHA512", "RSA");
        encryptionAlgs.put(PKCSObjectIdentifiers.rsaEncryption, "RSA");
        digestAlgs.put(NISTObjectIdentifiers.id_sha512, "SHA512");
    }

    /**
     * Return the digest algorithm using one of the standard JCA string
     * representations rather than the algorithm identifier (if possible).
     */
    private String getDigestAlgName(
            ASN1ObjectIdentifier digestAlgOID) {
        String algName = (String) digestAlgs.get(digestAlgOID);

        if (algName != null) {
            return algName;
        }

        return digestAlgOID.getId();
    }

    /**
     * Return the digest encryption algorithm using one of the standard
     * JCA string representations rather the the algorithm identifier (if
     * possible).
     */
    private String getEncryptionAlgName(
            ASN1ObjectIdentifier encryptionAlgOID) {
        String algName = (String) encryptionAlgs.get(encryptionAlgOID);

        if (algName != null) {
            return algName;
        }

        return encryptionAlgOID.getId();
    }

    public String getSignatureName(AlgorithmIdentifier digestAlg, AlgorithmIdentifier encryptionAlg) {
        String digestName = getDigestAlgName(encryptionAlg.getAlgorithm());

        if (!digestName.equals(encryptionAlg.getAlgorithm().getId())) {
            return digestName + "with" + getEncryptionAlgName(encryptionAlg.getAlgorithm());
        }
        return getDigestAlgName(digestAlg.getAlgorithm()) + "with" + getEncryptionAlgName(encryptionAlg.getAlgorithm());
    }
}