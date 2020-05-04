package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#section-6.2.2">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <p>
 * <pre>
 * RecipientKeyIdentifier ::= SEQUENCE {
 *     subjectKeyIdentifier SubjectKeyIdentifier,
 *     date GeneralizedTime OPTIONAL,
 *     other OtherKeyAttribute OPTIONAL
 * }
 *
 * SubjectKeyIdentifier ::= OCTET STRING
 * </pre>
 */
public class RecipientKeyIdentifier
        extends ASN1Object {
    private ASN1OctetString subjectKeyIdentifier;
    private ASN1GeneralizedTime date;
    private OtherKeyAttribute other;


    /**
     * @deprecated use getInstance()
     */
    public RecipientKeyIdentifier(
            ASN1Sequence seq) {
        subjectKeyIdentifier = ASN1OctetString.getInstance(
                seq.getObjectAt(0));

        switch (seq.size()) {
            case 1:
                break;
            case 2:
                if (seq.getObjectAt(1) instanceof ASN1GeneralizedTime) {
                    date = ASN1GeneralizedTime.getInstance(seq.getObjectAt(1));
                } else {
                    other = OtherKeyAttribute.getInstance(seq.getObjectAt(2));
                }
                break;
            case 3:
                date = ASN1GeneralizedTime.getInstance(seq.getObjectAt(1));
                other = OtherKeyAttribute.getInstance(seq.getObjectAt(2));
                break;
            default:
                throw new IllegalArgumentException("Invalid RecipientKeyIdentifier");
        }
    }

    /**
     * Return a RecipientKeyIdentifier object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link RecipientKeyIdentifier} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with RecipientKeyIdentifier structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static RecipientKeyIdentifier getInstance(Object obj) {
        if (obj instanceof RecipientKeyIdentifier) {
            return (RecipientKeyIdentifier) obj;
        }

        if (obj != null) {
            return new RecipientKeyIdentifier(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(subjectKeyIdentifier);

        if (date != null) {
            v.add(date);
        }

        if (other != null) {
            v.add(other);
        }

        return new DERSequence(v);
    }
}
