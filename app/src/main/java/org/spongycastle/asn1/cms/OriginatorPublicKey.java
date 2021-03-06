package org.spongycastle.asn1.cms;

import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#section-6.2.2">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <p>
 * <pre>
 * OriginatorPublicKey ::= SEQUENCE {
 *     algorithm AlgorithmIdentifier,
 *     publicKey BIT STRING
 * }
 * </pre>
 */
public class OriginatorPublicKey
        extends ASN1Object {
    private AlgorithmIdentifier algorithm;
    private DERBitString publicKey;


    /**
     * @deprecated use getInstance()
     */
    public OriginatorPublicKey(
            ASN1Sequence seq) {
        algorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        publicKey = (DERBitString) seq.getObjectAt(1);
    }

    /**
     * Return an OriginatorPublicKey object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link OriginatorPublicKey} object
     * <li> {@link org.spongycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with OriginatorPublicKey structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static OriginatorPublicKey getInstance(
            Object obj) {
        if (obj instanceof OriginatorPublicKey) {
            return (OriginatorPublicKey) obj;
        }

        if (obj != null) {
            return new OriginatorPublicKey(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(algorithm);
        v.add(publicKey);

        return new DERSequence(v);
    }
}
