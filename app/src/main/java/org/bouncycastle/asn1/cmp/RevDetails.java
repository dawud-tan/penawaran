package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.X509Extensions;

public class RevDetails
        extends ASN1Object {
    private CertTemplate certDetails;
    private Extensions crlEntryDetails;

    /**
     * @param certDetails
     * @param crlEntryDetails
     * @deprecated use method taking Extensions
     */
    public RevDetails(CertTemplate certDetails, X509Extensions crlEntryDetails) {
        this.certDetails = certDetails;
        this.crlEntryDetails = Extensions.getInstance(crlEntryDetails.toASN1Primitive());
    }

    /**
     * <pre>
     * RevDetails ::= SEQUENCE {
     *                  certDetails         CertTemplate,
     *                   -- allows requester to specify as much as they can about
     *                   -- the cert. for which revocation is requested
     *                   -- (e.g., for cases in which serialNumber is not available)
     *                   crlEntryDetails     Extensions       OPTIONAL
     *                   -- requested crlEntryExtensions
     *             }
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(certDetails);

        if (crlEntryDetails != null) {
            v.add(crlEntryDetails);
        }

        return new DERSequence(v);
    }
}
