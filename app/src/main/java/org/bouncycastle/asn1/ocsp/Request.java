package org.bouncycastle.asn1.ocsp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extensions;

public class Request
        extends ASN1Object {
    CertID reqCert;
    Extensions singleRequestExtensions;


    private Request(
            ASN1Sequence seq) {
        reqCert = CertID.getInstance(seq.getObjectAt(0));

        if (seq.size() == 2) {
            singleRequestExtensions = Extensions.getInstance(
                    (ASN1TaggedObject) seq.getObjectAt(1), true);
        }
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * Request         ::=     SEQUENCE {
     *     reqCert                     CertID,
     *     singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(reqCert);

        if (singleRequestExtensions != null) {
            v.add(new DERTaggedObject(true, 0, singleRequestExtensions));
        }

        return new DERSequence(v);
    }
}
