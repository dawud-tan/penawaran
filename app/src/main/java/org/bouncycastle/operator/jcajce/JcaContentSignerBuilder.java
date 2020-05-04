package org.bouncycastle.operator.jcajce;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.RuntimeOperatorException;

import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

public class JcaContentSignerBuilder {
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private SecureRandom random;
    private String signatureAlgorithm;
    private AlgorithmIdentifier sigAlgId;
    private AlgorithmParameterSpec sigAlgSpec;

    public JcaContentSignerBuilder(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        this.sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithm);
        this.sigAlgSpec = null;
    }


    public JcaContentSignerBuilder setProvider(String providerName) {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

    public ContentSigner build(PrivateKey privateKey)
            throws OperatorCreationException {
        try {
            final Signature sig = helper.createSignature(sigAlgId);
            final AlgorithmIdentifier signatureAlgId = sigAlgId;

            if (random != null) {
                sig.initSign(privateKey, random);
            } else {
                sig.initSign(privateKey);
            }

            return new ContentSigner() {
                private OutputStream stream = OutputStreamFactory.createStream(sig);

                public AlgorithmIdentifier getAlgorithmIdentifier() {
                    return signatureAlgId;
                }

                public OutputStream getOutputStream() {
                    return stream;
                }

                public byte[] getSignature() {
                    try {
                        return sig.sign();
                    } catch (SignatureException e) {
                        throw new RuntimeOperatorException("exception obtaining signature: " + e.getMessage(), e);
                    }
                }
            };
        } catch (GeneralSecurityException e) {
            throw new OperatorCreationException("cannot create signer: " + e.getMessage(), e);
        }
    }
}