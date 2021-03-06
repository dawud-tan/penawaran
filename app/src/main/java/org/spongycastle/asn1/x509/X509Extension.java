package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1Boolean;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Primitive;

import java.io.IOException;

/**
 * an object for the elements in the X.509 V3 extension block.
 *
 * @deprecated use Extension
 */
public class X509Extension {
    boolean critical;
    ASN1OctetString value;

    public X509Extension(
            ASN1Boolean critical,
            ASN1OctetString value) {
        this.critical = critical.isTrue();
        this.value = value;
    }

    public X509Extension(
            boolean critical,
            ASN1OctetString value) {
        this.critical = critical;
        this.value = value;
    }

    public boolean isCritical() {
        return critical;
    }

    public ASN1OctetString getValue() {
        return value;
    }

    public int hashCode() {
        if (this.isCritical()) {
            return this.getValue().hashCode();
        }

        return ~this.getValue().hashCode();
    }

    public boolean equals(
            Object o) {
        if (!(o instanceof X509Extension)) {
            return false;
        }

        X509Extension other = (X509Extension) o;

        return other.getValue().equals(this.getValue())
                && (other.isCritical() == this.isCritical());
    }

    /**
     * Convert the value of the passed in extension to an object
     *
     * @param ext the extension to parse
     * @return the object the value string contains
     * @throws IllegalArgumentException if conversion is not possible
     */
    public static ASN1Primitive convertValueToObject(
            X509Extension ext)
            throws IllegalArgumentException {
        try {
            return ASN1Primitive.fromByteArray(ext.getValue().getOctets());
        } catch (IOException e) {
            throw new IllegalArgumentException("can't convert extension: " + e);
        }
    }
}
