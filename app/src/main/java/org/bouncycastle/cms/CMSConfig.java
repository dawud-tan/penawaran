package org.bouncycastle.cms;

public class CMSConfig {
    /**
     * Set the mapping for the digest algorithm to use in conjunction with a SignedData generation
     * or interpretation.
     *
     * @param oid           object identifier to map.
     * @param algorithmName algorithm name to use.
     * @deprecated no longer required.
     */
    public static void setSigningDigestAlgorithmMapping(String oid, String algorithmName) {

    }
}
