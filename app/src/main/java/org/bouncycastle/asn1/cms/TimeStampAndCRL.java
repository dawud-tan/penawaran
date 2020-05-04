package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.CertificateList;

/**
 * <a href="http://tools.ietf.org/html/rfc5544">RFC 5544</a>
 * Binding Documents with Time-Stamps; TimeStampAndCRL object.
 * <pre>
 * TimeStampAndCRL ::= SEQUENCE {
 *     timeStamp   TimeStampToken,          -- according to RFC 3161
 *     crl         CertificateList OPTIONAL -- according to RFC 5280
 *  }
 * </pre>
 */
public class TimeStampAndCRL
        extends ASN1Object {
    private ContentInfo timeStamp;
    private CertificateList crl;


    private TimeStampAndCRL(ASN1Sequence seq) {
        this.timeStamp = ContentInfo.getInstance(seq.getObjectAt(0));
        if (seq.size() == 2) {
            this.crl = CertificateList.getInstance(seq.getObjectAt(1));
        }
    }


    /**
     * @deprecated use getCRL()
     */
    public CertificateList getCertificateList() {
        return this.crl;
    }


    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(timeStamp);

        if (crl != null) {
            v.add(crl);
        }

        return new DERSequence(v);
    }
}
