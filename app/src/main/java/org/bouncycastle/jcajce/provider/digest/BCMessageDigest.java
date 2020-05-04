package org.bouncycastle.jcajce.provider.digest;

import org.bouncycastle.crypto.Digest;

import java.security.MessageDigest;

public class BCMessageDigest
        extends MessageDigest {
    protected Digest digest;
    protected int digestSize;

    protected BCMessageDigest(
            Digest digest) {
        super(digest.getAlgorithmName());

        this.digest = digest;
        this.digestSize = digest.getDigestSize();
    }


    public void engineReset() {
        digest.reset();
    }

    public void engineUpdate(
            byte input) {
        digest.update(input);
    }

    public void engineUpdate(
            byte[] input,
            int offset,
            int len) {
        digest.update(input, offset, len);
    }

    public int engineGetDigestLength() {
        return digestSize;
    }

    public byte[] engineDigest() {
        byte[] digestBytes = new byte[digestSize];

        digest.doFinal(digestBytes, 0);

        return digestBytes;
    }
}
