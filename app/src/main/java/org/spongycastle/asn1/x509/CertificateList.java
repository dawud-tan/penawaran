
package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x500.X500Name;

import java.util.Enumeration;

/**
 * PKIX RFC-2459
 * <p>
 * The X.509 v2 CRL syntax is as follows.  For signature calculation,
 * the data that is to be signed is ASN.1 DER encoded.
 *
 * <pre>
 * CertificateList  ::=  SEQUENCE  {
 *      tbsCertList          TBSCertList,
 *      signatureAlgorithm   AlgorithmIdentifier,
 *      signatureValue       BIT STRING  }
 * </pre>
 */
public class CertificateList
        extends ASN1Object {
    TBSCertList tbsCertList;
    AlgorithmIdentifier sigAlgId;
    DERBitString sig;
    boolean isHashCodeSet = false;
    int hashCodeValue;

    public static CertificateList getInstance(
            Object obj) {
        if (obj instanceof CertificateList) {
            return (CertificateList) obj;
        } else if (obj != null) {
            return new CertificateList(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * @param seq
     * @deprecated use getInstance() method.
     */
    public CertificateList(
            ASN1Sequence seq) {
        if (seq.size() == 3) {
            tbsCertList = TBSCertList.getInstance(seq.getObjectAt(0));
            sigAlgId = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
            sig = DERBitString.getInstance(seq.getObjectAt(2));
        } else {
            throw new IllegalArgumentException("sequence wrong size for CertificateList");
        }
    }

    public TBSCertList getTBSCertList() {
        return tbsCertList;
    }


    public Enumeration getRevokedCertificateEnumeration() {
        return tbsCertList.getRevokedCertificateEnumeration();
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return sigAlgId;
    }

    public DERBitString getSignature() {
        return sig;
    }

    public int getVersionNumber() {
        return tbsCertList.getVersionNumber();
    }

    public X500Name getIssuer() {
        return tbsCertList.getIssuer();
    }

    public Time getThisUpdate() {
        return tbsCertList.getThisUpdate();
    }

    public Time getNextUpdate() {
        return tbsCertList.getNextUpdate();
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(tbsCertList);
        v.add(sigAlgId);
        v.add(sig);

        return new DERSequence(v);
    }

    public int hashCode() {
        if (!isHashCodeSet) {
            hashCodeValue = super.hashCode();
            isHashCodeSet = true;
        }

        return hashCodeValue;
    }
}
