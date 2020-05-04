package org.bouncycastle.operator.jcajce;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.MessageDigestUtils;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.HashMap;
import java.util.Map;

class OperatorHelper {
    private static final Map oids = new HashMap();

    static {
        //
        // reverse mappings
        //
        oids.put(NISTObjectIdentifiers.id_sha512, "SHA512");
    }

    private JcaJceHelper helper;

    OperatorHelper(JcaJceHelper helper) {
        this.helper = helper;
    }

    MessageDigest createDigest(AlgorithmIdentifier digAlgId)
            throws GeneralSecurityException {
        MessageDigest dig;

        try {
            dig = helper.createMessageDigest(MessageDigestUtils.getDigestName(digAlgId.getAlgorithm()));
        } catch (NoSuchAlgorithmException e) {
            //
            // try an alternate
            //
            if (oids.get(digAlgId.getAlgorithm()) != null) {
                String digestAlgorithm = "SHA512";

                dig = helper.createMessageDigest(digestAlgorithm);
            } else {
                throw e;
            }
        }

        return dig;
    }

    Signature createSignature(AlgorithmIdentifier sigAlgId)
            throws GeneralSecurityException {
        Signature sig;

        try {
            sig = helper.createSignature(getSignatureName(sigAlgId));
        } catch (NoSuchAlgorithmException e) {
            //
            // try an alternate
            //
            if (oids.get(sigAlgId.getAlgorithm()) != null) {
                String signatureAlgorithm = (String) oids.get(sigAlgId.getAlgorithm());

                sig = helper.createSignature(signatureAlgorithm);
            } else {
                throw e;
            }
        }


        return sig;
    }

    public Signature createRawSignature(AlgorithmIdentifier algorithm) {
        Signature sig;

        try {
            String algName = getSignatureName(algorithm);

            algName = "NONE" + algName.substring(algName.indexOf("WITH"));

            sig = helper.createSignature(algName);


        } catch (Exception e) {
            return null;
        }

        return sig;
    }

    private static String getSignatureName(
            AlgorithmIdentifier sigAlgId) {

        if (oids.containsKey(sigAlgId.getAlgorithm())) {
            return (String) oids.get(sigAlgId.getAlgorithm());
        }

        return sigAlgId.getAlgorithm().getId();
    }
}