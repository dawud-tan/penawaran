package org.bouncycastle.jce;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.X509Name;

import java.io.IOException;
import java.security.Principal;

/**
 * a general extension of X509Name with a couple of extra methods and
 * constructors.
 * <p>
 * Objects of this type can be created from certificates and CRLs using the
 * PrincipalUtil class.
 * </p>
 *
 * @deprecated use the X500Name class.
 */
public class X509Principal
        extends X509Name
        implements Principal {


    /**
     * Constructor from an X509Name object.
     */
    public X509Principal(
            X500Name name) {
        super((ASN1Sequence) name.toASN1Primitive());
    }


    public String getName() {
        return this.toString();
    }

    /**
     * return a DER encoded byte array representing this object
     */
    public byte[] getEncoded() {
        try {
            return this.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new RuntimeException(e.toString());
        }
    }
}