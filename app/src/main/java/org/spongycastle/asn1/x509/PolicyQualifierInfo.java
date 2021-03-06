package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERSequence;

/**
 * Policy qualifiers, used in the X509V3 CertificatePolicies
 * extension.
 *
 * <pre>
 *   PolicyQualifierInfo ::= SEQUENCE {
 *       policyQualifierId  PolicyQualifierId,
 *       qualifier          ANY DEFINED BY policyQualifierId }
 *
 *  PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
 * </pre>
 */
public class PolicyQualifierInfo
        extends ASN1Object {
    private ASN1ObjectIdentifier policyQualifierId;
    private ASN1Encodable qualifier;


    /**
     * Creates a new <code>PolicyQualifierInfo</code> instance.
     *
     * @param as <code>PolicyQualifierInfo</code> X509 structure
     *           encoded as an ASN1Sequence.
     * @deprecated use PolicyQualifierInfo.getInstance()
     */
    public PolicyQualifierInfo(
            ASN1Sequence as) {
        if (as.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: "
                    + as.size());
        }

        policyQualifierId = ASN1ObjectIdentifier.getInstance(as.getObjectAt(0));
        qualifier = as.getObjectAt(1);
    }

    public static PolicyQualifierInfo getInstance(
            Object obj) {
        if (obj instanceof PolicyQualifierInfo) {
            return (PolicyQualifierInfo) obj;
        } else if (obj != null) {
            return new PolicyQualifierInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }


    /**
     * Returns a DER-encodable representation of this instance.
     *
     * @return a <code>ASN1Primitive</code> value
     */
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector dev = new ASN1EncodableVector(2);
        dev.add(policyQualifierId);
        dev.add(qualifier);

        return new DERSequence(dev);
    }
}
