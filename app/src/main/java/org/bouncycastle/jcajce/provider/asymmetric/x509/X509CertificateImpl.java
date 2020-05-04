package org.bouncycastle.jcajce.provider.asymmetric.x509;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.jcajce.interfaces.BCX509Certificate;
import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

abstract class X509CertificateImpl
        extends X509Certificate
        implements BCX509Certificate {
    protected JcaJceHelper bcHelper;
    protected org.bouncycastle.asn1.x509.Certificate c;
    protected BasicConstraints basicConstraints;
    protected boolean[] keyUsage;
    protected String sigAlgName;
    protected byte[] sigAlgParams;

    X509CertificateImpl(JcaJceHelper bcHelper, org.bouncycastle.asn1.x509.Certificate c,
                        BasicConstraints basicConstraints, boolean[] keyUsage, String sigAlgName, byte[] sigAlgParams) {
        this.bcHelper = bcHelper;
        this.c = c;
        this.basicConstraints = basicConstraints;
        this.keyUsage = keyUsage;
        this.sigAlgName = sigAlgName;
        this.sigAlgParams = sigAlgParams;
    }


    public void checkValidity()
            throws CertificateExpiredException, CertificateNotYetValidException {
        this.checkValidity(new Date());
    }

    public void checkValidity(
            Date date)
            throws CertificateExpiredException, CertificateNotYetValidException {
        if (date.getTime() > this.getNotAfter().getTime())  // for other VM compatibility
        {
            throw new CertificateExpiredException("certificate expired on " + c.getEndDate().getTime());
        }

        if (date.getTime() < this.getNotBefore().getTime()) {
            throw new CertificateNotYetValidException("certificate not valid till " + c.getStartDate().getTime());
        }
    }

    public int getVersion() {
        return c.getVersionNumber();
    }

    public BigInteger getSerialNumber() {
        return c.getSerialNumber().getValue();
    }

    public Principal getIssuerDN() {
        return new X509Principal(c.getIssuer());
    }

    public X500Principal getIssuerX500Principal() {
        try {
            byte[] encoding = c.getIssuer().getEncoded(ASN1Encoding.DER);

            return new X500Principal(encoding);
        } catch (IOException e) {
            throw new IllegalStateException("can't encode issuer DN");
        }
    }

    public Principal getSubjectDN() {
        return new X509Principal(c.getSubject());
    }

    public X500Principal getSubjectX500Principal() {
        try {
            byte[] encoding = c.getSubject().getEncoded(ASN1Encoding.DER);

            return new X500Principal(encoding);
        } catch (IOException e) {
            throw new IllegalStateException("can't encode subject DN");
        }
    }

    public Date getNotBefore() {
        return c.getStartDate().getDate();
    }

    public Date getNotAfter() {
        return c.getEndDate().getDate();
    }

    public byte[] getTBSCertificate()
            throws CertificateEncodingException {
        try {
            return c.getTBSCertificate().getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new CertificateEncodingException(e.toString());
        }
    }

    public byte[] getSignature() {
        return c.getSignature().getOctets();
    }

    /**
     * return a more "meaningful" representation for the signature algorithm used in
     * the certificate.
     */
    public String getSigAlgName() {
        return sigAlgName;
    }

    /**
     * return the object identifier for the signature.
     */
    public String getSigAlgOID() {
        return c.getSignatureAlgorithm().getAlgorithm().getId();
    }

    /**
     * return the signature parameters, or null if there aren't any.
     */
    public byte[] getSigAlgParams() {
        return Arrays.clone(sigAlgParams);
    }

    public boolean[] getIssuerUniqueID() {
        DERBitString id = c.getTBSCertificate().getIssuerUniqueId();

        if (id != null) {
            byte[] bytes = id.getBytes();
            boolean[] boolId = new boolean[bytes.length * 8 - id.getPadBits()];

            for (int i = 0; i != boolId.length; i++) {
                boolId[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
            }

            return boolId;
        }

        return null;
    }

    public boolean[] getSubjectUniqueID() {
        DERBitString id = c.getTBSCertificate().getSubjectUniqueId();

        if (id != null) {
            byte[] bytes = id.getBytes();
            boolean[] boolId = new boolean[bytes.length * 8 - id.getPadBits()];

            for (int i = 0; i != boolId.length; i++) {
                boolId[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
            }

            return boolId;
        }

        return null;
    }

    public boolean[] getKeyUsage() {
        return Arrays.clone(keyUsage);
    }

    public List getExtendedKeyUsage()
            throws CertificateParsingException {
        byte[] extOctets = getExtensionOctets(c, "2.5.29.37");
        if (null == extOctets) {
            return null;
        }

        try {
            ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(extOctets));

            List list = new ArrayList();
            for (int i = 0; i != seq.size(); i++) {
                list.add(((ASN1ObjectIdentifier) seq.getObjectAt(i)).getId());
            }
            return Collections.unmodifiableList(list);
        } catch (Exception e) {
            throw new CertificateParsingException("error processing extended key usage extension");
        }
    }

    public int getBasicConstraints() {
        if (basicConstraints != null) {
            if (basicConstraints.isCA()) {
                if (basicConstraints.getPathLenConstraint() == null) {
                    return Integer.MAX_VALUE;
                } else {
                    return basicConstraints.getPathLenConstraint().intValue();
                }
            } else {
                return -1;
            }
        }

        return -1;
    }

    public Collection getSubjectAlternativeNames()
            throws CertificateParsingException {
        return getAlternativeNames(c, Extension.subjectAlternativeName.getId());
    }

    public Collection getIssuerAlternativeNames()
            throws CertificateParsingException {
        return getAlternativeNames(c, Extension.issuerAlternativeName.getId());
    }

    public Set getCriticalExtensionOIDs() {
        if (this.getVersion() == 3) {
            Set set = new HashSet();
            Extensions extensions = c.getTBSCertificate().getExtensions();

            if (extensions != null) {
                Enumeration e = extensions.oids();

                while (e.hasMoreElements()) {
                    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) e.nextElement();
                    Extension ext = extensions.getExtension(oid);

                    if (ext.isCritical()) {
                        set.add(oid.getId());
                    }
                }

                return set;
            }
        }

        return null;
    }

    public byte[] getExtensionValue(String oid) {
        ASN1OctetString extValue = getExtensionValue(c, oid);
        if (null != extValue) {
            try {
                return extValue.getEncoded();
            } catch (Exception e) {
                throw new IllegalStateException("error parsing " + e.toString());
            }
        }

        return null;
    }

    public Set getNonCriticalExtensionOIDs() {
        if (this.getVersion() == 3) {
            Set set = new HashSet();
            Extensions extensions = c.getTBSCertificate().getExtensions();

            if (extensions != null) {
                Enumeration e = extensions.oids();

                while (e.hasMoreElements()) {
                    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) e.nextElement();
                    Extension ext = extensions.getExtension(oid);

                    if (!ext.isCritical()) {
                        set.add(oid.getId());
                    }
                }

                return set;
            }
        }

        return null;
    }

    public boolean hasUnsupportedCriticalExtension() {
        if (this.getVersion() == 3) {
            Extensions extensions = c.getTBSCertificate().getExtensions();

            if (extensions != null) {
                Enumeration e = extensions.oids();

                while (e.hasMoreElements()) {
                    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) e.nextElement();

                    if (oid.equals(Extension.keyUsage)
                            || oid.equals(Extension.certificatePolicies)
                            || oid.equals(Extension.policyMappings)
                            || oid.equals(Extension.inhibitAnyPolicy)
                            || oid.equals(Extension.cRLDistributionPoints)
                            || oid.equals(Extension.issuingDistributionPoint)
                            || oid.equals(Extension.deltaCRLIndicator)
                            || oid.equals(Extension.policyConstraints)
                            || oid.equals(Extension.basicConstraints)
                            || oid.equals(Extension.subjectAlternativeName)
                            || oid.equals(Extension.nameConstraints)) {
                        continue;
                    }

                    Extension ext = extensions.getExtension(oid);

                    if (ext.isCritical()) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    public PublicKey getPublicKey() {
        try {
            return BouncyCastleProvider.getPublicKey(c.getSubjectPublicKeyInfo());
        } catch (IOException e) {
            return null;   // should never happen...
        }
    }

    public byte[] getEncoded()
            throws CertificateEncodingException {
        try {
            return c.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new CertificateEncodingException(e.toString());
        }
    }

    public String toString() {
        return X509CertificateImpl.class.getCanonicalName();
    }

    public final void verify(
            PublicKey key)
            throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException {
        Signature signature;
        String sigName = X509SignatureUtil.getSignatureName(c.getSignatureAlgorithm());

        try {
            signature = bcHelper.createSignature(sigName);
        } catch (Exception e) {
            signature = Signature.getInstance(sigName);
        }

        checkSignature(key, signature);
    }

    public final void verify(
            PublicKey key,
            String sigProvider)
            throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException {
        String sigName = X509SignatureUtil.getSignatureName(c.getSignatureAlgorithm());
        Signature signature;

        if (sigProvider != null) {
            signature = Signature.getInstance(sigName, sigProvider);
        } else {
            signature = Signature.getInstance(sigName);
        }

        checkSignature(key, signature);
    }

    public final void verify(
            PublicKey key,
            Provider sigProvider)
            throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {
        String sigName = X509SignatureUtil.getSignatureName(c.getSignatureAlgorithm());
        Signature signature;

        if (sigProvider != null) {
            signature = Signature.getInstance(sigName, sigProvider);
        } else {
            signature = Signature.getInstance(sigName);
        }

        checkSignature(key, signature);
    }

    private void checkSignature(
            PublicKey key,
            Signature signature)
            throws CertificateException, NoSuchAlgorithmException,
            SignatureException, InvalidKeyException {
        if (!isAlgIdEqual(c.getSignatureAlgorithm(), c.getTBSCertificate().getSignature())) {
            throw new CertificateException("signature algorithm in TBS cert not same as outer cert");
        }

        ASN1Encodable params = c.getSignatureAlgorithm().getParameters();

        // TODO This should go after the initVerify?
        X509SignatureUtil.setSignatureParameters(signature, params);

        signature.initVerify(key);

        try {
            OutputStream sigOut = new BufferedOutputStream(OutputStreamFactory.createStream(signature), 512);

            c.getTBSCertificate().encodeTo(sigOut, ASN1Encoding.DER);

            sigOut.close();
        } catch (IOException e) {
            throw new CertificateEncodingException(e.toString());
        }

        if (!signature.verify(this.getSignature())) {
            throw new SignatureException("certificate does not verify with supplied key");
        }
    }

    private boolean isAlgIdEqual(AlgorithmIdentifier id1, AlgorithmIdentifier id2) {
        if (!id1.getAlgorithm().equals(id2.getAlgorithm())) {
            return false;
        }

        if (id1.getParameters() == null) {
            return id2.getParameters() == null || id2.getParameters().equals(DERNull.INSTANCE);
        }

        if (id2.getParameters() == null) {
            return id1.getParameters() == null || id1.getParameters().equals(DERNull.INSTANCE);
        }

        return id1.getParameters().equals(id2.getParameters());
    }

    private static Collection getAlternativeNames(org.bouncycastle.asn1.x509.Certificate c, String oid)
            throws CertificateParsingException {
        byte[] extOctets = getExtensionOctets(c, oid);
        if (extOctets == null) {
            return null;
        }
        try {
            Collection temp = new ArrayList();
            Enumeration it = ASN1Sequence.getInstance(extOctets).getObjects();
            while (it.hasMoreElements()) {
                GeneralName genName = GeneralName.getInstance(it.nextElement());
                List list = new ArrayList();
                list.add(Integers.valueOf(genName.getTagNo()));
                switch (genName.getTagNo()) {
                    case GeneralName.ediPartyName:
                    case GeneralName.x400Address:
                    case GeneralName.otherName:
                        list.add(genName.getEncoded());
                        break;
                    case GeneralName.directoryName:
                        list.add(X500Name.getInstance(RFC4519Style.INSTANCE, genName.getName()).toString());
                        break;
                    case GeneralName.dNSName:
                    case GeneralName.rfc822Name:
                    case GeneralName.uniformResourceIdentifier:
                        list.add(((ASN1String) genName.getName()).getString());
                        break;
                    case GeneralName.registeredID:
                        list.add(ASN1ObjectIdentifier.getInstance(genName.getName()).getId());
                        break;
                    case GeneralName.iPAddress:
                        byte[] addrBytes = DEROctetString.getInstance(genName.getName()).getOctets();
                        final String addr;
                        try {
                            addr = InetAddress.getByAddress(addrBytes).getHostAddress();
                        } catch (UnknownHostException e) {
                            continue;
                        }
                        list.add(addr);
                        break;
                    default:
                        throw new IOException("Bad tag number: " + genName.getTagNo());
                }

                temp.add(Collections.unmodifiableList(list));
            }
            if (temp.size() == 0) {
                return null;
            }
            return Collections.unmodifiableCollection(temp);
        } catch (Exception e) {
            throw new CertificateParsingException(e.getMessage());
        }
    }

    protected static byte[] getExtensionOctets(org.bouncycastle.asn1.x509.Certificate c, String oid) {
        ASN1OctetString extValue = getExtensionValue(c, oid);
        if (null != extValue) {
            return extValue.getOctets();
        }
        return null;
    }

    protected static ASN1OctetString getExtensionValue(org.bouncycastle.asn1.x509.Certificate c, String oid) {
        Extensions exts = c.getTBSCertificate().getExtensions();
        if (null != exts) {
            Extension ext = exts.getExtension(new ASN1ObjectIdentifier(oid));
            if (null != ext) {
                return ext.getExtnValue();
            }
        }
        return null;
    }
}