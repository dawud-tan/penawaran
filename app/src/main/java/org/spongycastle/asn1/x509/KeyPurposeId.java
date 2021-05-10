package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.ASN1Primitive;

/**
 * The KeyPurposeId object.
 * <pre>
 *     KeyPurposeId ::= OBJECT IDENTIFIER
 *
 *     id-kp ::= OBJECT IDENTIFIER { iso(1) identified-organization(3)
 *          dod(6) internet(1) security(5) mechanisms(5) pkix(7) 3}
 *
 * </pre>
 * To create a new KeyPurposeId where none of the below suit, use
 * <pre>
 *     ASN1ObjectIdentifier newKeyPurposeIdOID = new ASN1ObjectIdentifier("1.3.6.1...");
 *
 *     KeyPurposeId newKeyPurposeId = KeyPurposeId.getInstance(newKeyPurposeIdOID);
 * </pre>
 */
public class KeyPurposeId
        extends ASN1Object {
    private ASN1ObjectIdentifier id;

    private KeyPurposeId(ASN1ObjectIdentifier id) {
        this.id = id;
    }

    /**
     * @param id string representation of an OID.
     * @deprecated use getInstance and an OID or one of the constants above.
     */
    public KeyPurposeId(String id) {
        this(new ASN1ObjectIdentifier(id));
    }

    public static KeyPurposeId getInstance(Object o) {
        if (o instanceof KeyPurposeId) {
            return (KeyPurposeId) o;
        } else if (o != null) {
            return new KeyPurposeId(ASN1ObjectIdentifier.getInstance(o));
        }

        return null;
    }


    public ASN1Primitive toASN1Primitive() {
        return id;
    }


    public String toString() {
        return id.toString();
    }
}
