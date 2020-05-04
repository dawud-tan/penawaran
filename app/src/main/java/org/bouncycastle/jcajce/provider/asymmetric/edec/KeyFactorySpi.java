package org.bouncycastle.jcajce.provider.asymmetric.edec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

public class KeyFactorySpi
        extends BaseKeyFactorySpi
        implements AsymmetricKeyInfoConverter {
    static final byte[] Ed25519Prefix = Hex.decode("302a300506032b6570032100");

    private static final byte Ed25519_type = 0x70;

    String algorithm;
    private final boolean isXdh;
    private final int specificBase;

    public KeyFactorySpi(
            String algorithm,
            boolean isXdh,
            int specificBase) {
        this.algorithm = algorithm;
        this.isXdh = isXdh;
        this.specificBase = specificBase;
    }

    protected Key engineTranslateKey(
            Key key)
            throws InvalidKeyException {
        throw new InvalidKeyException("key type unknown");
    }

    protected KeySpec engineGetKeySpec(
            Key key,
            Class spec)
            throws InvalidKeySpecException {

        return super.engineGetKeySpec(key, spec);
    }

    protected PrivateKey engineGeneratePrivate(
            KeySpec keySpec)
            throws InvalidKeySpecException {
        return super.engineGeneratePrivate(keySpec);
    }

    protected PublicKey engineGeneratePublic(
            KeySpec keySpec)
            throws InvalidKeySpecException {
        if (keySpec instanceof X509EncodedKeySpec) {
            byte[] enc = ((X509EncodedKeySpec) keySpec).getEncoded();
            // optimise if we can
            if ((specificBase == 0 || specificBase == enc[8])) {
                // watch out for badly placed DER NULL - the default X509Cert will add these!
                if (enc[9] == 0x05 && enc[10] == 0x00) {
                    SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(enc);

                    keyInfo = new SubjectPublicKeyInfo(
                            new AlgorithmIdentifier(keyInfo.getAlgorithm().getAlgorithm()), keyInfo.getPublicKeyData().getBytes());

                    try {
                        enc = keyInfo.getEncoded(ASN1Encoding.DER);
                    } catch (IOException e) {
                        throw new InvalidKeySpecException("attempt to reconstruct key failed: " + e.getMessage());
                    }
                }

                switch (enc[8]) {
                    case Ed25519_type:
                        return new BCEdDSAPublicKey(Ed25519Prefix, enc);
                    default:
                        return super.engineGeneratePublic(keySpec);
                }
            }
        }

        return super.engineGeneratePublic(keySpec);
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
            throws IOException {
        return new BCEdDSAPrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
            throws IOException {
        return new BCEdDSAPublicKey(keyInfo);
    }

    public static class Ed25519
            extends KeyFactorySpi {
        public Ed25519() {
            super("Ed25519", false, Ed25519_type);
        }
    }
}