package org.bouncycastle.operator.jcajce;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.MessageDigestUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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
                String digestAlgorithm = (String) oids.get(digAlgId.getAlgorithm());

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


    public X509Certificate convertCertificate(X509CertificateHolder certHolder)
            throws CertificateException {
        try {
            CertificateFactory certFact = helper.createCertificateFactory("X.509");

            return (X509Certificate) certFact.generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
        } catch (IOException e) {
            throw new OpCertificateException("cannot get encoded form of certificate: " + e.getMessage(), e);
        } catch (NoSuchProviderException e) {
            throw new OpCertificateException("cannot find factory provider: " + e.getMessage(), e);
        }
    }


    // TODO: put somewhere public so cause easily accessed
    private static class OpCertificateException
            extends CertificateException {
        private Throwable cause;

        public OpCertificateException(String msg, Throwable cause) {
            super(msg);

            this.cause = cause;
        }

        public Throwable getCause() {
            return cause;
        }
    }
}