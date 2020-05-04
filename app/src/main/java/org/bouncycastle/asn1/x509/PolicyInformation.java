package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class PolicyInformation
        extends ASN1Object {
    private ASN1ObjectIdentifier policyIdentifier;
    private ASN1Sequence policyQualifiers;

    private PolicyInformation(
            ASN1Sequence seq) {
        if (seq.size() < 1 || seq.size() > 2) {
            throw new IllegalArgumentException("Bad sequence size: "
                    + seq.size());
        }

        policyIdentifier = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));

        if (seq.size() > 1) {
            policyQualifiers = ASN1Sequence.getInstance(seq.getObjectAt(1));
        }
    }

    /*
     * <pre>
     * PolicyInformation ::= SEQUENCE {
     *      policyIdentifier   CertPolicyId,
     *      policyQualifiers   SEQUENCE SIZE (1..MAX) OF
     *              PolicyQualifierInfo OPTIONAL }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(policyIdentifier);

        if (policyQualifiers != null) {
            v.add(policyQualifiers);
        }

        return new DERSequence(v);
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();

        sb.append("Policy information: ");
        sb.append(policyIdentifier);

        if (policyQualifiers != null) {
            StringBuffer p = new StringBuffer();
            for (int i = 0; i < policyQualifiers.size(); i++) {
                if (p.length() != 0) {
                    p.append(", ");
                }
                p.append(PolicyQualifierInfo.getInstance(policyQualifiers.getObjectAt(i)));
            }

            sb.append("[");
            sb.append(p);
            sb.append("]");
        }

        return sb.toString();
    }
}
