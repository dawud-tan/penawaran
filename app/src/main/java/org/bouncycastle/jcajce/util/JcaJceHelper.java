package org.bouncycastle.jcajce.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/**
 * Factory interface for instantiating JCA/JCE primitives.
 */
public interface JcaJceHelper {


    /**
     * @deprecated Use createMessageDigest instead
     */
    MessageDigest createDigest(String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException;

    MessageDigest createMessageDigest(String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException;

    Signature createSignature(String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException;

    CertificateFactory createCertificateFactory(String algorithm)
            throws NoSuchProviderException, CertificateException;


}
