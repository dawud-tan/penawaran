package org.spongycastle.jcajce.io;

import java.io.OutputStream;
import java.security.Signature;

/**
 * Utility class for creating OutputStreams from different JCA/JCE operators.
 */
public class OutputStreamFactory {
    /**
     * Create an OutputStream that wraps a signature.
     *
     * @param signature the signature to be updated as the stream is written to.
     * @return an OutputStream.
     */
    public static OutputStream createStream(Signature signature) {
        return new SignatureUpdatingOutputStream(signature);
    }

}
