package org.bouncycastle.jcajce.util;

import java.security.PrivateKey;
import java.util.Collections;
import java.util.Map;

/**
 * Wrapper for a private key that carries annotations that can be used
 * for tracking or debugging.
 */
public class AnnotatedPrivateKey
        implements PrivateKey {
    public static final String LABEL = "label";

    private final PrivateKey key;
    private final Map<String, Object> annotations;

    AnnotatedPrivateKey(PrivateKey key, String label) {
        this.key = key;
        this.annotations = Collections.singletonMap(LABEL, label);
    }

    AnnotatedPrivateKey(PrivateKey key, Map<String, Object> annotations) {
        this.key = key;
        this.annotations = annotations;
    }

    public PrivateKey getKey() {
        return key;
    }


    public String getAlgorithm() {
        return key.getAlgorithm();
    }


    public String getFormat() {
        return key.getFormat();
    }

    public byte[] getEncoded() {
        return key.getEncoded();
    }

    public int hashCode() {
        return this.key.hashCode();
    }

    public boolean equals(Object o) {
        if (o instanceof AnnotatedPrivateKey) {
            return this.key.equals(((AnnotatedPrivateKey) o).key);
        }
        return this.key.equals(o);
    }

    public String toString() {
        if (annotations.containsKey(LABEL)) {
            return annotations.get(LABEL).toString();
        }

        return key.toString();
    }
}
