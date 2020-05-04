package org.bouncycastle.crypto.params;

import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.util.Arrays;

public final class Ed25519PrivateKeyParameters
        extends AsymmetricKeyParameter {
    public static final int KEY_SIZE = Ed25519.SECRET_KEY_SIZE;
    public static final int SIGNATURE_SIZE = Ed25519.SIGNATURE_SIZE;

    private final byte[] data = new byte[KEY_SIZE];

    private Ed25519PublicKeyParameters cachedPublicKey;

    public Ed25519PrivateKeyParameters(byte[] buf, int off) {
        super(true);

        System.arraycopy(buf, off, data, 0, KEY_SIZE);
    }


    public byte[] getEncoded() {
        return Arrays.clone(data);
    }

    public Ed25519PublicKeyParameters generatePublicKey() {
        synchronized (data) {
            if (null == cachedPublicKey) {
                byte[] publicKey = new byte[Ed25519.PUBLIC_KEY_SIZE];
                Ed25519.generatePublicKey(data, 0, publicKey, 0);
                cachedPublicKey = new Ed25519PublicKeyParameters(publicKey, 0);
            }
            return cachedPublicKey;
        }
    }

    public void sign(int algorithm, byte[] ctx, byte[] msg, int msgOff, int msgLen, byte[] sig, int sigOff) {
        Ed25519PublicKeyParameters publicKey = generatePublicKey();
        byte[] pk = new byte[Ed25519.PUBLIC_KEY_SIZE];
        publicKey.encode(pk, 0);
        if (null != ctx) {
            throw new IllegalArgumentException("ctx");
        }
        Ed25519.sign(data, 0, pk, 0, msg, msgOff, msgLen, sig, sigOff);
    }
}