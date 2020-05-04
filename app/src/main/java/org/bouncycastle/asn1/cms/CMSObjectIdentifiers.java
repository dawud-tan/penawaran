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


    /**
     * The other Revocation Info arc
     * <p>
     * <pre>
     * id-ri OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
     *        dod(6) internet(1) security(5) mechanisms(5) pkix(7) ri(16) }
     * </pre>
     */
    ASN1ObjectIdentifier id_ri = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.16");

    /**
     * 1.3.6.1.5.5.7.16.2
     */
    ASN1ObjectIdentifier id_ri_ocsp_response = id_ri.branch("2");
}
