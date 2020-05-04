package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import java.util.Enumeration;
import java.util.Vector;

/**
 * This extension may contain further X.500 attributes of the subject. See also
 * RFC 3039.
 *
 * <pre>
 *     SubjectDirectoryAttributes ::= Attributes
 *     Attributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
 *     Attribute ::= SEQUENCE
 *     {
 *       type AttributeType
 *       values SET OF AttributeValue
 *     }
 *
 *     AttributeType ::= OBJECT IDENTIFIER
 *     AttributeValue ::= ANY DEFINED BY AttributeType
 * </pre>
 *
 * @see org.bouncycastle.asn1.x500.style.BCStyle for AttributeType ObjectIdentifiers.
 */
public class SubjectDirectoryAttributes
        extends ASN1Object {
    private Vector attributes = new Vector();

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <p>
     * Returns:
     *
     * <pre>
     *      SubjectDirectoryAttributes ::= Attributes
     *      Attributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
     *      Attribute ::= SEQUENCE
     *      {
     *        type AttributeType
     *        values SET OF AttributeValue
     *      }
     *
     *      AttributeType ::= OBJECT IDENTIFIER
     *      AttributeValue ::= ANY DEFINED BY AttributeType
     * </pre>
     *
     * @return a ASN1Primitive
     */
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector(attributes.size());

        Enumeration e = attributes.elements();
        while (e.hasMoreElements()) {
            vec.add((Attribute) e.nextElement());
        }

        return new DERSequence(vec);
    }

}
