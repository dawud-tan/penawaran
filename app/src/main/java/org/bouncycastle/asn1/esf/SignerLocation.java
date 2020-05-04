package org.bouncycastle.asn1.esf;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.DirectoryString;

/**
 * Signer-Location attribute (RFC3126).
 *
 * <pre>
 *   SignerLocation ::= SEQUENCE {
 *       countryName        [0] DirectoryString OPTIONAL,
 *       localityName       [1] DirectoryString OPTIONAL,
 *       postalAddress      [2] PostalAddress OPTIONAL }
 *
 *   PostalAddress ::= SEQUENCE SIZE(1..6) OF DirectoryString
 * </pre>
 */
public class SignerLocation
        extends ASN1Object {
    private DirectoryString countryName;
    private DirectoryString localityName;
    private ASN1Sequence postalAddress;

    /**
     * Return the countryName DirectoryString
     *
     * @return the countryName, null if absent.
     */
    public DirectoryString getCountry() {
        return countryName;
    }

    /**
     * Return the localityName DirectoryString
     *
     * @return the localityName, null if absent.
     */
    public DirectoryString getLocality() {
        return localityName;
    }


    /**
     * @deprecated use getCountry()
     */
    public DERUTF8String getCountryName() {
        if (countryName == null) {
            return null;
        }
        return new DERUTF8String(getCountry().getString());
    }

    /**
     * @deprecated use getLocality()
     */
    public DERUTF8String getLocalityName() {
        if (localityName == null) {
            return null;
        }
        return new DERUTF8String(getLocality().getString());
    }


    /**
     * <pre>
     *   SignerLocation ::= SEQUENCE {
     *       countryName        [0] DirectoryString OPTIONAL,
     *       localityName       [1] DirectoryString OPTIONAL,
     *       postalAddress      [2] PostalAddress OPTIONAL }
     *
     *   PostalAddress ::= SEQUENCE SIZE(1..6) OF DirectoryString
     *
     *   DirectoryString ::= CHOICE {
     *         teletexString           TeletexString (SIZE (1..MAX)),
     *         printableString         PrintableString (SIZE (1..MAX)),
     *         universalString         UniversalString (SIZE (1..MAX)),
     *         utf8String              UTF8String (SIZE (1.. MAX)),
     *         bmpString               BMPString (SIZE (1..MAX)) }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        if (countryName != null) {
            v.add(new DERTaggedObject(true, 0, countryName));
        }

        if (localityName != null) {
            v.add(new DERTaggedObject(true, 1, localityName));
        }

        if (postalAddress != null) {
            v.add(new DERTaggedObject(true, 2, postalAddress));
        }

        return new DERSequence(v);
    }
}
