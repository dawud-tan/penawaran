package org.bouncycastle.jcajce.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/**
 * {@link JcaJceHelper} that obtains all algorithms using the default JCA/JCE mechanism (i.e.
 * without specifying a provider).
 */
public class DefaultJcaJceHelper
        implements JcaJceHelper {


    /**
     * @deprecated Use createMessageDigest instead
     */
    public MessageDigest createDigest(String algorithm)
            throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(algorithm);
    }

    public MessageDigest createMessageDigest(String algorithm)
            throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(algorithm);
    }

    public Signature createSignature(String algorithm)
            throws NoSuchAlgorithmException {
        return Signature.getInstance(algorithm);
    }

    public CertificateFactory createCertificateFactory(String algorithm)
            throws CertificateException {
        return CertificateFactory.getInstance(algorithm);
    }


}
