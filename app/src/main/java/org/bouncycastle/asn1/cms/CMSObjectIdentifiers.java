package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

public interface CMSObjectIdentifiers {
    /**
     * PKCS#7: 1.2.840.113549.1.7.1
     */
    ASN1ObjectIdentifier data = PKCSObjectIdentifiers.data;
    /**
     * PKCS#7: 1.2.840.113549.1.7.2
     */
    ASN1ObjectIdentifier signedData = PKCSObjectIdentifiers.signedData;
}
