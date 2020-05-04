package org.bouncycastle.asn1.pkcs;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * a PKCS#7 signer info object.
 */
public class SignerInfo
        extends ASN1Object {
    private ASN1Integer version;
    private IssuerAndSerialNumber issuerAndSerialNumber;
    private AlgorithmIdentifier digAlgorithm;
    private ASN1Set authenticatedAttributes;
    private AlgorithmIdentifier digEncryptionAlgorithm;
    private ASN1OctetString encryptedDigest;
    private ASN1Set unauthenticatedAttributes;

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  SignerInfo ::= SEQUENCE {
     *      version Version,
     *      issuerAndSerialNumber IssuerAndSerialNumber,
     *      digestAlgorithm DigestAlgorithmIdentifier,
     *      authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL,
     *      digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
     *      encryptedDigest EncryptedDigest,
     *      unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL
     *  }
     *
     *  EncryptedDigest ::= OCTET STRING
     *
     *  DigestAlgorithmIdentifier ::= AlgorithmIdentifier
     *
     *  DigestEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
     * </pre>
     */
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(7);

        v.add(version);
        v.add(issuerAndSerialNumber);
        v.add(digAlgorithm);

        if (authenticatedAttributes != null) {
            v.add(new DERTaggedObject(false, 0, authenticatedAttributes));
        }

        v.add(digEncryptionAlgorithm);
        v.add(encryptedDigest);

        if (unauthenticatedAttributes != null) {
            v.add(new DERTaggedObject(false, 1, unauthenticatedAttributes));
        }

        return new DERSequence(v);
    }
}
