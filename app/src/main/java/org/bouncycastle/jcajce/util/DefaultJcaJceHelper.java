package org.bouncycastle.jcajce.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

/**
 * {@link JcaJceHelper} that obtains all algorithms using the default JCA/JCE mechanism (i.e.
 * without specifying a provider).
 */
public class DefaultJcaJceHelper
        implements JcaJceHelper {
    public MessageDigest createMessageDigest(String algorithm)
            throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(algorithm);
    }

    public Signature createSignature(String algorithm)
            throws NoSuchAlgorithmException {
        return Signature.getInstance(algorithm);
    }
}