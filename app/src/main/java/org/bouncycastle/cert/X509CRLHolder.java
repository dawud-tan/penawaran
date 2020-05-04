package org.bouncycastle.cert;

import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.util.Encodable;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

/**
 * Holding class for an X.509 CRL structure.
 */
public class X509CRLHolder
        implements Encodable, Serializable {
    private static final long serialVersionUID = 20170722001L;

    private transient CertificateList x509CRL;
    private transient boolean isIndirect;
    private transient Extensions extensions;
    private transient GeneralNames issuerName;

    private static boolean isIndirectCRL(Extensions extensions) {
        if (extensions == null) {
            return false;
        }

        Extension ext = extensions.getExtension(Extension.issuingDistributionPoint);

        return ext != null && IssuingDistributionPoint.getInstance(ext.getParsedValue()).isIndirectCRL();
    }


    private void init(CertificateList x509CRL) {
        this.x509CRL = x509CRL;
        this.extensions = x509CRL.getTBSCertList().getExtensions();
        this.isIndirect = isIndirectCRL(extensions);
        this.issuerName = new GeneralNames(new GeneralName(x509CRL.getIssuer()));
    }

    /**
     * Return the ASN.1 encoding of this holder's CRL.
     *
     * @return a DER encoded byte array.
     * @throws IOException if an encoding cannot be generated.
     */
    public byte[] getEncoded()
            throws IOException {
        return x509CRL.getEncoded();
    }

    /**
     * Return the underlying ASN.1 structure for the CRL in this holder.
     *
     * @return a CertificateList object.
     */
    public CertificateList toASN1Structure() {
        return x509CRL;
    }


    public boolean equals(
            Object o) {
        if (o == this) {
            return true;
        }

        if (!(o instanceof X509CRLHolder)) {
            return false;
        }

        X509CRLHolder other = (X509CRLHolder) o;

        return this.x509CRL.equals(other.x509CRL);
    }

    public int hashCode() {
        return this.x509CRL.hashCode();
    }

    private void readObject(
            ObjectInputStream in)
            throws IOException, ClassNotFoundException {
        in.defaultReadObject();

        init(CertificateList.getInstance(in.readObject()));
    }

    private void writeObject(
            ObjectOutputStream out)
            throws IOException {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}