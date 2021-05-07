package org.bouncycastle.jcajce.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;

/**
 * Factory interface for instantiating JCA/JCE primitives.
 */
public interface JcaJceHelper {
    MessageDigest createMessageDigest(String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException;

    Signature createSignature(String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException;
}
