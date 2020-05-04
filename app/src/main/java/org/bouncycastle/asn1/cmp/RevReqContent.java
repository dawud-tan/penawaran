package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

public class RevReqContent
        extends ASN1Object {
    private ASN1Sequence content;

    private RevReqContent(ASN1Sequence seq) {
        content = seq;
    }

    public static RevReqContent getInstance(Object o) {
        if (o instanceof RevReqContent) {
            return (RevReqContent) o;
        }

        if (o != null) {
            return new RevReqContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }


    /**
     * <pre>
     * RevReqContent ::= SEQUENCE OF RevDetails
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive() {
        return content;
    }
}
