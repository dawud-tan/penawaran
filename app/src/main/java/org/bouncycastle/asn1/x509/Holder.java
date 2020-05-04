package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * The Holder object.
 * <p>
 * For an v2 attribute certificate this is:
 *
 * <pre>
 *            Holder ::= SEQUENCE {
 *                  baseCertificateID   [0] IssuerSerial OPTIONAL,
 *                           -- the issuer and serial number of
 *                           -- the holder's Public Key Certificate
 *                  entityName          [1] GeneralNames OPTIONAL,
 *                           -- the name of the claimant or role
 *                  objectDigestInfo    [2] ObjectDigestInfo OPTIONAL
 *                           -- used to directly authenticate the holder,
 *                           -- for example, an executable
 *            }
 * </pre>
 *
 * <p>
 * For an v1 attribute certificate this is:
 *
 * <pre>
 *         subject CHOICE {
 *          baseCertificateID [0] EXPLICIT IssuerSerial,
 *          -- associated with a Public Key Certificate
 *          subjectName [1] EXPLICIT GeneralNames },
 *          -- associated with a name
 * </pre>
 */
public class Holder
        extends ASN1Object {
    public static final int V1_CERTIFICATE_HOLDER = 0;
    public static final int V2_CERTIFICATE_HOLDER = 1;

    IssuerSerial baseCertificateID;

    GeneralNames entityName;

    ObjectDigestInfo objectDigestInfo;

    private int version = V2_CERTIFICATE_HOLDER;


    /**
     * Constructor for a holder for an V1 attribute certificate.
     *
     * @param tagObj The ASN.1 tagged holder object.
     */
    private Holder(ASN1TaggedObject tagObj) {
        switch (tagObj.getTagNo()) {
            case 0:
                baseCertificateID = IssuerSerial.getInstance(tagObj, true);
                break;
            case 1:
                entityName = GeneralNames.getInstance(tagObj, true);
                break;
            default:
                throw new IllegalArgumentException("unknown tag in Holder");
        }
        version = 0;
    }

    /**
     * Constructor for a holder for an V2 attribute certificate.
     *
     * @param seq The ASN.1 sequence.
     */
    private Holder(ASN1Sequence seq) {
        if (seq.size() > 3) {
            throw new IllegalArgumentException("Bad sequence size: "
                    + seq.size());
        }

        for (int i = 0; i != seq.size(); i++) {
            ASN1TaggedObject tObj = ASN1TaggedObject.getInstance(seq
                    .getObjectAt(i));

            switch (tObj.getTagNo()) {
                case 0:
                    baseCertificateID = IssuerSerial.getInstance(tObj, false);
                    break;
                case 1:
                    entityName = GeneralNames.getInstance(tObj, false);
                    break;
                case 2:
                    objectDigestInfo = ObjectDigestInfo.getInstance(tObj, false);
                    break;
                default:
                    throw new IllegalArgumentException("unknown tag in Holder");
            }
        }
        version = 1;
    }


    public ASN1Primitive toASN1Primitive() {
        if (version == 1) {
            ASN1EncodableVector v = new ASN1EncodableVector(3);

            if (baseCertificateID != null) {
                v.add(new DERTaggedObject(false, 0, baseCertificateID));
            }

            if (entityName != null) {
                v.add(new DERTaggedObject(false, 1, entityName));
            }

            if (objectDigestInfo != null) {
                v.add(new DERTaggedObject(false, 2, objectDigestInfo));
            }

            return new DERSequence(v);
        } else {
            if (entityName != null) {
                return new DERTaggedObject(true, 1, entityName);
            } else {
                return new DERTaggedObject(true, 0, baseCertificateID);
            }
        }
    }
}
