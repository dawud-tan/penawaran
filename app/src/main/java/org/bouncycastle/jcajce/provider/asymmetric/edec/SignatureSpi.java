package org.bouncycastle.jcajce.provider.asymmetric.edec;


import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

public class SignatureSpi
        extends java.security.SignatureSpi {
    private static final byte[] EMPTY_CONTEXT = new byte[0];

    private final String algorithm;

    private Signer signer;

    SignatureSpi(String algorithm) {
        this.algorithm = algorithm;
    }

    protected void engineInitVerify(PublicKey publicKey)
            throws InvalidKeyException {
        if (publicKey instanceof BCEdDSAPublicKey) {
            AsymmetricKeyParameter pub = ((BCEdDSAPublicKey) publicKey).engineGetKeyParameters();
            signer = getSigner("Ed25519");
            signer.init(false, pub);
        } else {
            throw new InvalidKeyException("cannot identify EdDSA public key");
        }
    }

    protected void engineInitSign(PrivateKey privateKey)
            throws InvalidKeyException {
        if (privateKey instanceof BCEdDSAPrivateKey) {
            AsymmetricKeyParameter priv = ((BCEdDSAPrivateKey) privateKey).engineGetKeyParameters();
            signer = getSigner("Ed25519");
            signer.init(true, priv);
        } else {
            throw new InvalidKeyException("cannot identify EdDSA private key");
        }
    }

    private Signer getSigner(String alg)
            throws InvalidKeyException {
        if (algorithm != null && !alg.equals(algorithm)) {
            throw new InvalidKeyException("inappropriate key for " + algorithm);
        }
        return new Ed25519Signer();
    }

    protected void engineUpdate(byte b)
            throws SignatureException {
        signer.update(b);
    }

    protected void engineUpdate(byte[] bytes, int off, int len)
            throws SignatureException {
        signer.update(bytes, off, len);
    }

    protected byte[] engineSign()
            throws SignatureException {
        try {
            return signer.generateSignature();
        } catch (CryptoException e) {
            throw new SignatureException(e.getMessage());
        }
    }

    protected boolean engineVerify(byte[] signature)
            throws SignatureException {
        return signer.verifySignature(signature);
    }

    protected void engineSetParameter(String s, Object o)
            throws InvalidParameterException {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    protected Object engineGetParameter(String s)
            throws InvalidParameterException {
        throw new UnsupportedOperationException("engineGetParameter unsupported");
    }

    public final static class Ed25519
            extends SignatureSpi {
        public Ed25519() {
            super("Ed25519");
        }
    }
}