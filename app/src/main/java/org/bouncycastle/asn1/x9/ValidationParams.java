package org.bouncycastle.asn1.x9;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;

/**
 * Diffie-Hellman domain validation parameters.
 * <pre>
 * ValidationParams ::= SEQUENCE {
 *    seed         BIT STRING,
 *    pgenCounter  INTEGER
 * }
 * </pre>
 */
public class ValidationParams
        extends ASN1Object {
    private DERBitString seed;
    private ASN1Integer pgenCounter;


    public static ValidationParams getInstance(Object obj) {
        if (obj instanceof ValidationParams) {
            return (ValidationParams) obj;
        } else if (obj != null) {
            return new ValidationParams(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private ValidationParams(ASN1Sequence seq) {
        if (seq.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        this.seed = DERBitString.getInstance(seq.getObjectAt(0));
        this.pgenCounter = ASN1Integer.getInstance(seq.getObjectAt(1));
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.seed);
        v.add(this.pgenCounter);
        return new DERSequence(v);
    }
}
