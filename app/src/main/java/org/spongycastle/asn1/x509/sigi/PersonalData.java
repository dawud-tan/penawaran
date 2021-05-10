package org.spongycastle.asn1.x509.sigi;

import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1GeneralizedTime;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.DERPrintableString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.x500.DirectoryString;

import java.math.BigInteger;

/**
 * Contains personal data for the otherName field in the subjectAltNames
 * extension.
 *
 * <pre>
 *     PersonalData ::= SEQUENCE {
 *       nameOrPseudonym NameOrPseudonym,
 *       nameDistinguisher [0] INTEGER OPTIONAL,
 *       dateOfBirth [1] GeneralizedTime OPTIONAL,
 *       placeOfBirth [2] DirectoryString OPTIONAL,
 *       gender [3] PrintableString OPTIONAL,
 *       postalAddress [4] DirectoryString OPTIONAL
 *       }
 * </pre>
 *
 * @see org.spongycastle.asn1.x509.sigi.NameOrPseudonym
 * @see org.spongycastle.asn1.x509.sigi.SigIObjectIdentifiers
 */
public class PersonalData
        extends ASN1Object {
    private NameOrPseudonym nameOrPseudonym;
    private BigInteger nameDistinguisher;
    private ASN1GeneralizedTime dateOfBirth;
    private DirectoryString placeOfBirth;
    private String gender;
    private DirectoryString postalAddress;

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <p>
     * Returns:
     * <pre>
     *     PersonalData ::= SEQUENCE {
     *       nameOrPseudonym NameOrPseudonym,
     *       nameDistinguisher [0] INTEGER OPTIONAL,
     *       dateOfBirth [1] GeneralizedTime OPTIONAL,
     *       placeOfBirth [2] DirectoryString OPTIONAL,
     *       gender [3] PrintableString OPTIONAL,
     *       postalAddress [4] DirectoryString OPTIONAL
     *       }
     * </pre>
     *
     * @return a DERObject
     */
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector(6);
        vec.add(nameOrPseudonym);
        if (nameDistinguisher != null) {
            vec.add(new DERTaggedObject(false, 0, new ASN1Integer(nameDistinguisher)));
        }
        if (dateOfBirth != null) {
            vec.add(new DERTaggedObject(false, 1, dateOfBirth));
        }
        if (placeOfBirth != null) {
            vec.add(new DERTaggedObject(true, 2, placeOfBirth));
        }
        if (gender != null) {
            vec.add(new DERTaggedObject(false, 3, new DERPrintableString(gender, true)));
        }
        if (postalAddress != null) {
            vec.add(new DERTaggedObject(true, 4, postalAddress));
        }
        return new DERSequence(vec);
    }
}
