package org.bouncycastle.operator.jcajce;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

public class JcaDigestCalculatorProviderBuilder {
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());

    public JcaDigestCalculatorProviderBuilder() {
    }

    public DigestCalculatorProvider build() {
        return algorithm -> {
            final DigestOutputStream stream;

            try {
                MessageDigest dig = helper.createDigest(algorithm);

                stream = new DigestOutputStream(dig);
            } catch (GeneralSecurityException e) {
                throw new OperatorCreationException("exception on setup: " + e, e);
            }

            return new DigestCalculator() {
                public AlgorithmIdentifier getAlgorithmIdentifier() {
                    return algorithm;
                }

                public OutputStream getOutputStream() {
                    return stream;
                }

                public byte[] getDigest() {
                    return stream.getDigest();
                }
            };
        };
    }

    private class DigestOutputStream
            extends OutputStream {
        private MessageDigest dig;

        DigestOutputStream(MessageDigest dig) {
            this.dig = dig;
        }

        public void write(byte[] bytes, int off, int len)
                throws IOException {
            dig.update(bytes, off, len);
        }

        public void write(byte[] bytes)
                throws IOException {
            dig.update(bytes);
        }

        public void write(int b)
                throws IOException {
            dig.update((byte) b);
        }

        byte[] getDigest() {
            return dig.digest();
        }
    }
}