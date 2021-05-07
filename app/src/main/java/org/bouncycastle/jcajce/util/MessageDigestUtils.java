package org.bouncycastle.jcajce.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

import java.util.HashMap;
import java.util.Map;

public class MessageDigestUtils {
    private static Map<ASN1ObjectIdentifier, String> digestOidMap = new HashMap<ASN1ObjectIdentifier, String>();

    static {
        digestOidMap.put(NISTObjectIdentifiers.id_sha512, "SHA-512");
    }

    /**
     * Attempt to find a standard JCA name for the digest represented by the passed in OID.
     *
     * @param digestAlgOID the OID of the digest algorithm of interest.
     * @return a string representing the standard name - the OID as a string if none available.
     */
    public static String getDigestName(ASN1ObjectIdentifier digestAlgOID) {
        String name = (String) digestOidMap.get(digestAlgOID);  // for pre 1.5 JDK
        if (name != null) {
            return name;
        }
        return digestAlgOID.getId();
    }
}