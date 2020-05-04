package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;

import java.math.BigInteger;

/**
 * @deprecated use org.bouncycastle.asn1.pkcs.RSAPublicKey
 */
public class RSAPublicKeyStructure
        extends ASN1Object {
    private BigInteger modulus;
    private BigInteger publicExponent;


    public BigInteger getModulus() {
        return modulus;
    }

    public BigInteger getPublicExponent() {
        return publicExponent;
    }

    /**
     * This outputs the key in PKCS1v2 format.
     * <pre>
     *      RSAPublicKey ::= SEQUENCE {
     *                          modulus INTEGER, -- n
     *                          publicExponent INTEGER, -- e
     *                      }
     * </pre>
     * <p>
     */
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(new ASN1Integer(getModulus()));
        v.add(new ASN1Integer(getPublicExponent()));

        return new DERSequence(v);
    }
}
