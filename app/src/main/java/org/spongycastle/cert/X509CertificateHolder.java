package org.spongycastle.cert;

import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.x509.Certificate;
import org.spongycastle.asn1.x509.Extension;
import org.spongycastle.asn1.x509.Extensions;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.util.Encodable;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Date;

/**
 * Holding class for an X.509 Certificate structure.
 */
public class X509CertificateHolder
        implements Encodable, Serializable {
    private static final long serialVersionUID = 20170722001L;

    private transient Certificate x509Certificate;
    private transient Extensions extensions;

    /**
     * Create a X509CertificateHolder from the passed in ASN.1 structure.
     *
     * @param x509Certificate an ASN.1 Certificate structure.
     */
    public X509CertificateHolder(Certificate x509Certificate) {
        init(x509Certificate);
    }

    private void init(Certificate x509Certificate) {
        this.x509Certificate = x509Certificate;
        this.extensions = x509Certificate.getTBSCertificate().getExtensions();
    }

    /**
     * @deprecated use getVersionNumber
     */
    public int getVersion() {
        return x509Certificate.getVersionNumber();
    }

    /**
     * Look up the extension associated with the passed in OID.
     *
     * @param oid the OID of the extension of interest.
     * @return the extension if present, null otherwise.
     */
    public Extension getExtension(ASN1ObjectIdentifier oid) {
        if (extensions != null) {
            return extensions.getExtension(oid);
        }

        return null;
    }


    /**
     * Return the SubjectPublicKeyInfo describing the public key this certificate is carrying.
     *
     * @return the public key ASN.1 structure contained in the certificate.
     */
    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
        return x509Certificate.getSubjectPublicKeyInfo();
    }

    /**
     * Return the underlying ASN.1 structure for the certificate in this holder.
     *
     * @return a Certificate object.
     */
    public Certificate toASN1Structure() {
        return x509Certificate;
    }


    /**
     * Return whether or not this certificate is valid on a particular date.
     *
     * @param date the date of interest.
     * @return true if the certificate is valid, false otherwise.
     */
    public boolean isValidOn(Date date) {
        return !date.before(x509Certificate.getStartDate().getDate()) && !date.after(x509Certificate.getEndDate().getDate());
    }


    public boolean equals(
            Object o) {
        if (o == this) {
            return true;
        }

        if (!(o instanceof X509CertificateHolder)) {
            return false;
        }

        X509CertificateHolder other = (X509CertificateHolder) o;

        return this.x509Certificate.equals(other.x509Certificate);
    }

    public int hashCode() {
        return this.x509Certificate.hashCode();
    }

    /**
     * Return the ASN.1 encoding of this holder's certificate.
     *
     * @return a DER encoded byte array.
     * @throws IOException if an encoding cannot be generated.
     */
    public byte[] getEncoded()
            throws IOException {
        return x509Certificate.getEncoded();
    }

    private void readObject(
            ObjectInputStream in)
            throws IOException, ClassNotFoundException {
        in.defaultReadObject();

        init(Certificate.getInstance(in.readObject()));
    }

    private void writeObject(
            ObjectOutputStream out)
            throws IOException {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
