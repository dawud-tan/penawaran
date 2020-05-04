package org.bouncycastle.crypto;

/**
 * the foundation class for the hard exceptions thrown by the crypto packages.
 */
public class CryptoException
        extends Exception {
    private Throwable cause;


    public Throwable getCause() {
        return cause;
    }
}
