package org.bouncycastle.asn1.smime;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

public class SMIMECapability
        extends ASN1Object {
    /**
     * general preferences
     */
    public static final ASN1ObjectIdentifier preferSignedData = PKCSObjectIdentifiers.preferSignedData;
    public static final ASN1ObjectIdentifier canNotDecryptAny = PKCSObjectIdentifiers.canNotDecryptAny;
    public static final ASN1ObjectIdentifier sMIMECapabilitiesVersions = PKCSObjectIdentifiers.sMIMECapabilitiesVersions;

    /**
     * encryption algorithms preferences
     */
    public static final ASN1ObjectIdentifier dES_CBC = new ASN1ObjectIdentifier("1.3.14.3.2.7");
    public static final ASN1ObjectIdentifier dES_EDE3_CBC = PKCSObjectIdentifiers.des_EDE3_CBC;
    public static final ASN1ObjectIdentifier rC2_CBC = PKCSObjectIdentifiers.RC2_CBC;
    public static final ASN1ObjectIdentifier aES128_CBC = NISTObjectIdentifiers.id_aes128_CBC;
    public static final ASN1ObjectIdentifier aES192_CBC = NISTObjectIdentifiers.id_aes192_CBC;
    public static final ASN1ObjectIdentifier aES256_CBC = NISTObjectIdentifiers.id_aes256_CBC;

    private ASN1ObjectIdentifier capabilityID;
    private ASN1Encodable parameters;

    public SMIMECapability(
            ASN1Sequence seq) {
        capabilityID = (ASN1ObjectIdentifier) seq.getObjectAt(0);

        if (seq.size() > 1) {
            parameters = seq.getObjectAt(1);
        }
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * SMIMECapability ::= SEQUENCE {
     *     capabilityID OBJECT IDENTIFIER,
     *     parameters ANY DEFINED BY capabilityID OPTIONAL
     * }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(capabilityID);

        if (parameters != null) {
            v.add(parameters);
        }

        return new DERSequence(v);
    }
}
