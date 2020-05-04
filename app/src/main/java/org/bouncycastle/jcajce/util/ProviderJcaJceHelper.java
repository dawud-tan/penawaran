package org.bouncycastle.jcajce.util;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/**
 * {@link JcaJceHelper} that obtains all algorithms from a specific {@link Provider} instance.
 */
public class ProviderJcaJceHelper
        implements JcaJceHelper {
    protected final Provider provider;

    public ProviderJcaJceHelper(Provider provider) {
        this.provider = provider;
    }

    /**
     * @deprecated Use createMessageDigest instead
     */
    public MessageDigest createDigest(String algorithm)
            throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(algorithm, provider);
    }

    public MessageDigest createMessageDigest(String algorithm)
            throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(algorithm, provider);
    }

    public Signature createSignature(String algorithm)
            throws NoSuchAlgorithmException {
        return Signature.getInstance(algorithm, provider);
    }

    public CertificateFactory createCertificateFactory(String algorithm)
            throws CertificateException {
        return CertificateFactory.getInstance(algorithm, provider);
    }


}