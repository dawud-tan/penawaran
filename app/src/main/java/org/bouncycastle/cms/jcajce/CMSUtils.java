package org.bouncycastle.cms.jcajce;

import org.bouncycastle.jcajce.util.AnnotatedPrivateKey;

import java.security.PrivateKey;

class CMSUtils {
    static PrivateKey cleanPrivateKey(PrivateKey key) {
        if (key instanceof AnnotatedPrivateKey) {
            return cleanPrivateKey(((AnnotatedPrivateKey) key).getKey());
        } else {
            return key;
        }
    }
}