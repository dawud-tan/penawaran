package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;

import java.util.Enumeration;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#section-5.1">RFC 5652</a>:
 * <p>
 * A signed data object containing multitude of {@link SignerInfo}s.
 * <pre>
 * SignedData ::= SEQUENCE {
 *     version CMSVersion,
 *     digestAlgorithms DigestAlgorithmIdentifiers,
 *     encapContentInfo EncapsulatedContentInfo,
 *     certificates [0] IMPLICIT CertificateSet OPTIONAL,
 *     crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
 *     signerInfos SignerInfos
 *   }
 *
 * DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
 *
 * SignerInfos ::= SET OF SignerInfo
 * </pre>
 * <p>
 * The version calculation uses following ruleset from RFC 5652 section 5.1:
 * <pre>
 * IF ((certificates is present) AND
 *    (any certificates with a type of other are present)) OR
 *    ((crls is present) AND
 *    (any crls with a type of other are present))
 * THEN version MUST be 5
 * ELSE
 *    IF (certificates is present) AND
 *       (any version 2 attribute certificates are present)
 *    THEN version MUST be 4
 *    ELSE
 *       IF ((certificates is present) AND
 *          (any version 1 attribute certificates are present)) OR
 *          (any SignerInfo structures are version 3) OR
 *          (encapContentInfo eContentType is other than id-data)
 *       THEN version MUST be 3
 *       ELSE version MUST be 1
 * </pre>
 * <p>
 */
public class SignedData
        extends ASN1Object {
    private static final ASN1Integer VERSION_1 = new ASN1Integer(1);
    private static final ASN1Integer VERSION_3 = new ASN1Integer(3);
    private static final ASN1Integer VERSION_4 = new ASN1Integer(4);
    private static final ASN1Integer VERSION_5 = new ASN1Integer(5);

    private ASN1Integer version;
    private ASN1Set digestAlgorithms;
    private ContentInfo contentInfo;
    private ASN1Set certificates;
    private ASN1Set crls;
    private ASN1Set signerInfos;
    private boolean certsBer;
    private boolean crlsBer;

    /**
     * Return a SignedData object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link SignedData} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with SignedData structure inside
     * </ul>
     *
     * @param o the object we want converted.
     * @return a reference that can be assigned to SignedData (may be null)
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static SignedData getInstance(
            Object o) {
        if (o instanceof SignedData) {
            return (SignedData) o;
        } else if (o != null) {
            return new SignedData(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private SignedData(
            ASN1Sequence seq) {
        Enumeration e = seq.getObjects();

        version = ASN1Integer.getInstance(e.nextElement());
        digestAlgorithms = ((ASN1Set) e.nextElement());
        contentInfo = ContentInfo.getInstance(e.nextElement());

        while (e.hasMoreElements()) {
            ASN1Primitive o = (ASN1Primitive) e.nextElement();

            //
            // an interesting feature of SignedData is that there appear
            // to be varying implementations...
            // for the moment we ignore anything which doesn't fit.
            //
            if (o instanceof ASN1TaggedObject) {
                ASN1TaggedObject tagged = (ASN1TaggedObject) o;

                switch (tagged.getTagNo()) {
                    case 0:
                        certsBer = tagged instanceof BERTaggedObject;
                        certificates = ASN1Set.getInstance(tagged, false);
                        break;
                    case 1:
                        crlsBer = tagged instanceof BERTaggedObject;
                        crls = ASN1Set.getInstance(tagged, false);
                        break;
                    default:
                        throw new IllegalArgumentException("unknown tag value " + tagged.getTagNo());
                }
            } else {
                signerInfos = (ASN1Set) o;
            }
        }
    }


    public ContentInfo getEncapContentInfo() {
        return contentInfo;
    }


    public ASN1Set getSignerInfos() {
        return signerInfos;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(6);

        v.add(version);
        v.add(digestAlgorithms);
        v.add(contentInfo);

        if (certificates != null) {
            if (certsBer) {
                v.add(new BERTaggedObject(false, 0, certificates));
            } else {
                v.add(new DERTaggedObject(false, 0, certificates));
            }
        }

        if (crls != null) {
            if (crlsBer) {
                v.add(new BERTaggedObject(false, 1, crls));
            } else {
                v.add(new DERTaggedObject(false, 1, crls));
            }
        }

        v.add(signerInfos);

        return new BERSequence(v);
    }
}
