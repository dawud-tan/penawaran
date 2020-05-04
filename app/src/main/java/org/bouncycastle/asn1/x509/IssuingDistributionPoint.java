package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

/**
 * <pre>
 * IssuingDistributionPoint ::= SEQUENCE {
 *   distributionPoint          [0] DistributionPointName OPTIONAL,
 *   onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
 *   onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
 *   onlySomeReasons            [3] ReasonFlags OPTIONAL,
 *   indirectCRL                [4] BOOLEAN DEFAULT FALSE,
 *   onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
 * </pre>
 */
public class IssuingDistributionPoint
        extends ASN1Object {
    private DistributionPointName distributionPoint;

    private boolean onlyContainsUserCerts;

    private boolean onlyContainsCACerts;

    private ReasonFlags onlySomeReasons;

    private boolean indirectCRL;

    private boolean onlyContainsAttributeCerts;

    private ASN1Sequence seq;

    public static IssuingDistributionPoint getInstance(
            ASN1TaggedObject obj,
            boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static IssuingDistributionPoint getInstance(
            Object obj) {
        if (obj instanceof IssuingDistributionPoint) {
            return (IssuingDistributionPoint) obj;
        } else if (obj != null) {
            return new IssuingDistributionPoint(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * Constructor from ASN1Sequence
     */
    private IssuingDistributionPoint(
            ASN1Sequence seq) {
        this.seq = seq;

        for (int i = 0; i != seq.size(); i++) {
            ASN1TaggedObject o = ASN1TaggedObject.getInstance(seq.getObjectAt(i));

            switch (o.getTagNo()) {
                case 0:
                    // CHOICE so explicit
                    distributionPoint = DistributionPointName.getInstance(o, true);
                    break;
                case 1:
                    onlyContainsUserCerts = ASN1Boolean.getInstance(o, false).isTrue();
                    break;
                case 2:
                    onlyContainsCACerts = ASN1Boolean.getInstance(o, false).isTrue();
                    break;
                case 3:
                    onlySomeReasons = new ReasonFlags(ReasonFlags.getInstance(o, false));
                    break;
                case 4:
                    indirectCRL = ASN1Boolean.getInstance(o, false).isTrue();
                    break;
                case 5:
                    onlyContainsAttributeCerts = ASN1Boolean.getInstance(o, false).isTrue();
                    break;
                default:
                    throw new IllegalArgumentException(
                            "unknown tag in IssuingDistributionPoint");
            }
        }
    }

    public boolean isIndirectCRL() {
        return indirectCRL;
    }

    public ASN1Primitive toASN1Primitive() {
        return seq;
    }

    public String toString() {
        return IssuingDistributionPoint.class.getCanonicalName();
    }
}
