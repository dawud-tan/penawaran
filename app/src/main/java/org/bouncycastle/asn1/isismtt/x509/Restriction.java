package org.bouncycastle.asn1.isismtt.x509;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.DirectoryString;

/**
 * Some other restriction regarding the usage of this certificate.
 *
 * <pre>
 *  RestrictionSyntax ::= DirectoryString (SIZE(1..1024))
 * </pre>
 */
public class Restriction
        extends ASN1Object {
    private DirectoryString restriction;


    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <p>
     * Returns:
     * <pre>
     *      RestrictionSyntax ::= DirectoryString (SIZE(1..1024))
     * </pre>
     *
     * @return a DERObject
     */
    public ASN1Primitive toASN1Primitive() {
        return restriction.toASN1Primitive();
    }
}
