package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x500.X500Name;

/**
 * an X509Certificate structure.
 * <pre>
 *  Certificate ::= SEQUENCE {
 *      tbsCertificate          TBSCertificate,
 *      signatureAlgorithm      AlgorithmIdentifier,
 *      signature               BIT STRING
 *  }
 * </pre>
 *
 * @deprecated use org.spongycastle.asn1.x509.Certificate
 */
public class X509CertificateStructure
        extends ASN1Object
        implements X509ObjectIdentifiers, PKCSObjectIdentifiers {
    ASN1Sequence seq;
    TBSCertificateStructure tbsCert;
    AlgorithmIdentifier sigAlgId;
    DERBitString sig;


    public X509CertificateStructure(
            ASN1Sequence seq) {
        this.seq = seq;

        //
        // correct x509 certficate
        //
        if (seq.size() == 3) {
            tbsCert = TBSCertificateStructure.getInstance(seq.getObjectAt(0));
            sigAlgId = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));

            sig = DERBitString.getInstance(seq.getObjectAt(2));
        } else {
            throw new IllegalArgumentException("sequence wrong size for a certificate");
        }
    }

    public ASN1Integer getSerialNumber() {
        return tbsCert.getSerialNumber();
    }

    public X500Name getIssuer() {
        return tbsCert.getIssuer();
    }


    public ASN1Primitive toASN1Primitive() {
        return seq;
    }
}
