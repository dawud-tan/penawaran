package org.bouncycastle.jcajce.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/**
 * {@link JcaJceHelper} that obtains all algorithms using a specific named provider.
 */
public class NamedJcaJceHelper
        implements JcaJceHelper {
    protected final String providerName;

    public NamedJcaJceHelper(String providerName) {
        this.providerName = providerName;
    }


    /**
     * @deprecated Use createMessageDigest instead
     */
    public MessageDigest createDigest(String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return MessageDigest.getInstance(algorithm, providerName);
    }

    public MessageDigest createMessageDigest(String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return MessageDigest.getInstance(algorithm, providerName);
    }

    public Signature createSignature(String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return Signature.getInstance(algorithm, providerName);
    }

    public CertificateFactory createCertificateFactory(String algorithm)
            throws CertificateException, NoSuchProviderException {
        return CertificateFactory.getInstance(algorithm, providerName);
    }

}