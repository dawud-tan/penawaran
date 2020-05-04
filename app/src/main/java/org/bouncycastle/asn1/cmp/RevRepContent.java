package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

import java.util.Enumeration;

public class RevRepContent
        extends ASN1Object {
    private ASN1Sequence status;
    private ASN1Sequence revCerts;
    private ASN1Sequence crls;

    private RevRepContent(ASN1Sequence seq) {
        Enumeration en = seq.getObjects();

        status = ASN1Sequence.getInstance(en.nextElement());
        while (en.hasMoreElements()) {
            ASN1TaggedObject tObj = ASN1TaggedObject.getInstance(en.nextElement());

            if (tObj.getTagNo() == 0) {
                revCerts = ASN1Sequence.getInstance(tObj, true);
            } else {
                crls = ASN1Sequence.getInstance(tObj, true);
            }
        }
    }

    public static RevRepContent getInstance(Object o) {
        if (o instanceof RevRepContent) {
            return (RevRepContent) o;
        }

        if (o != null) {
            return new RevRepContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    /**
     * <pre>
     * RevRepContent ::= SEQUENCE {
     *        status       SEQUENCE SIZE (1..MAX) OF PKIStatusInfo,
     *        -- in same order as was sent in RevReqContent
     *        revCerts [0] SEQUENCE SIZE (1..MAX) OF CertId OPTIONAL,
     *        -- IDs for which revocation was requested
     *        -- (same order as status)
     *        crls     [1] SEQUENCE SIZE (1..MAX) OF CertificateList OPTIONAL
     *        -- the resulting CRLs (there may be more than one)
     *   }
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(status);

        addOptional(v, 0, revCerts);
        addOptional(v, 1, crls);

        return new DERSequence(v);
    }

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj) {
        if (obj != null) {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }
}
