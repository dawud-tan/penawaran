package org.bouncycastle.cert;

import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.util.Encodable;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

/**
 * Holding class for an X.509 AttributeCertificate structure.
 */
public class X509AttributeCertificateHolder
        implements Encodable, Serializable {
    private static final long serialVersionUID = 20170722001L;


    private transient AttributeCertificate attrCert;
    private transient Extensions extensions;


    private void init(AttributeCertificate attrCert) {
        this.attrCert = attrCert;
        this.extensions = attrCert.getAcinfo().getExtensions();
    }

    /**
     * Return the ASN.1 encoding of this holder's attribute certificate.
     *
     * @return a DER encoded byte array.
     * @throws IOException if an encoding cannot be generated.
     */
    public byte[] getEncoded()
            throws IOException {
        return attrCert.getEncoded();
    }


    /**
     * Return the underlying ASN.1 structure for the attribute certificate in this holder.
     *
     * @return a AttributeCertificate object.
     */
    public AttributeCertificate toASN1Structure() {
        return attrCert;
    }


    public boolean equals(
            Object o) {
        if (o == this) {
            return true;
        }

        if (!(o instanceof X509AttributeCertificateHolder)) {
            return false;
        }

        X509AttributeCertificateHolder other = (X509AttributeCertificateHolder) o;

        return this.attrCert.equals(other.attrCert);
    }

    public int hashCode() {
        return this.attrCert.hashCode();
    }

    private void readObject(
            ObjectInputStream in)
            throws IOException, ClassNotFoundException {
        in.defaultReadObject();

        init(AttributeCertificate.getInstance(in.readObject()));
    }

    private void writeObject(
            ObjectOutputStream out)
            throws IOException {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
