package org.spongycastle.cms;

import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Encoding;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.ASN1Set;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.cms.Attribute;
import org.spongycastle.asn1.cms.AttributeTable;
import org.spongycastle.asn1.cms.CMSAlgorithmProtection;
import org.spongycastle.asn1.cms.CMSAttributes;
import org.spongycastle.asn1.cms.IssuerAndSerialNumber;
import org.spongycastle.asn1.cms.SignerIdentifier;
import org.spongycastle.asn1.cms.SignerInfo;
import org.spongycastle.asn1.cms.Time;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.DigestInfo;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.operator.ContentVerifier;
import org.spongycastle.operator.DigestCalculator;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.RawContentVerifier;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.io.TeeOutputStream;

import java.io.IOException;
import java.io.OutputStream;

/**
 * an expanded SignerInfo block from a CMS Signed message
 */
public class SignerInformation {
    private final SignerId sid;
    private final CMSProcessable content;
    private final byte[] signature;
    private final ASN1ObjectIdentifier contentType;
    private final boolean isCounterSignature;

    // Derived
    private AttributeTable signedAttributeValues;
    private AttributeTable unsignedAttributeValues;
    private byte[] resultDigest;

    protected final SignerInfo info;
    protected final AlgorithmIdentifier digestAlgorithm;
    protected final AlgorithmIdentifier encryptionAlgorithm;
    protected final ASN1Set signedAttributeSet;
    protected final ASN1Set unsignedAttributeSet;

    SignerInformation(
            SignerInfo info,
            ASN1ObjectIdentifier contentType,
            CMSProcessable content,
            byte[] resultDigest) {
        this.info = info;
        this.contentType = contentType;
        this.isCounterSignature = contentType == null;

        SignerIdentifier s = info.getSID();

        if (s.isTagged()) {
            ASN1OctetString octs = ASN1OctetString.getInstance(s.getId());

            sid = new SignerId(octs.getOctets());
        } else {
            IssuerAndSerialNumber iAnds = IssuerAndSerialNumber.getInstance(s.getId());

            sid = new SignerId(iAnds.getName(), iAnds.getSerialNumber().getValue());
        }

        this.digestAlgorithm = info.getDigestAlgorithm();
        this.signedAttributeSet = info.getAuthenticatedAttributes();
        this.unsignedAttributeSet = info.getUnauthenticatedAttributes();
        this.encryptionAlgorithm = info.getDigestEncryptionAlgorithm();
        this.signature = info.getEncryptedDigest().getOctets();

        this.content = content;
        this.resultDigest = resultDigest;
    }


    public SignerId getSID() {
        return sid;
    }


    public AlgorithmIdentifier getDigestAlgorithmID() {
        return digestAlgorithm;
    }

    /**
     * return the object identifier for the signature.
     */
    public String getEncryptionAlgOID() {
        return encryptionAlgorithm.getAlgorithm().getId();
    }


    /**
     * return a table of the signed attributes - indexed by
     * the OID of the attribute.
     */
    public AttributeTable getSignedAttributes() {
        if (signedAttributeSet != null && signedAttributeValues == null) {
            signedAttributeValues = new AttributeTable(signedAttributeSet);
        }

        return signedAttributeValues;
    }

    /**
     * return a table of the unsigned attributes indexed by
     * the OID of the attribute.
     */
    public AttributeTable getUnsignedAttributes() {
        if (unsignedAttributeSet != null && unsignedAttributeValues == null) {
            unsignedAttributeValues = new AttributeTable(unsignedAttributeSet);
        }

        return unsignedAttributeValues;
    }

    /**
     * return the encoded signature
     */
    public byte[] getSignature() {
        return Arrays.clone(signature);
    }


    /**
     * return the DER encoding of the signed attributes.
     *
     * @throws IOException if an encoding error occurs.
     */
    public byte[] getEncodedSignedAttributes()
            throws IOException {
        if (signedAttributeSet != null) {
            return signedAttributeSet.getEncoded(ASN1Encoding.DER);
        }

        return null;
    }

    private boolean doVerify(
            SignerInformationVerifier verifier)
            throws CMSException {
        String encName = CMSSignedHelper.INSTANCE.getEncryptionAlgName(this.getEncryptionAlgOID());
        ContentVerifier contentVerifier;

        try {
            contentVerifier = verifier.getContentVerifier(encryptionAlgorithm, info.getDigestAlgorithm());
        } catch (OperatorCreationException e) {
            throw new CMSException("can't create content verifier: " + e.getMessage(), e);
        }

        try {
            OutputStream sigOut = contentVerifier.getOutputStream();

            if (resultDigest == null) {
                DigestCalculator calc = verifier.getDigestCalculator(this.getDigestAlgorithmID());
                if (content != null) {
                    OutputStream digOut = calc.getOutputStream();

                    if (signedAttributeSet == null) {
                        if (contentVerifier instanceof RawContentVerifier) {
                            content.write(digOut);
                        } else {
                            OutputStream cOut = new TeeOutputStream(digOut, sigOut);

                            content.write(cOut);

                            cOut.close();
                        }
                    } else {
                        content.write(digOut);
                        sigOut.write(this.getEncodedSignedAttributes());
                    }

                    digOut.close();
                } else if (signedAttributeSet != null) {
                    sigOut.write(this.getEncodedSignedAttributes());
                } else {
                    // TODO Get rid of this exception and just treat content==null as empty not missing?
                    throw new CMSException("data not encapsulated in signature - use detached constructor.");
                }

                resultDigest = calc.getDigest();
            } else {
                if (signedAttributeSet == null) {
                    if (content != null) {
                        content.write(sigOut);
                    }
                } else {
                    sigOut.write(this.getEncodedSignedAttributes());
                }
            }

            sigOut.close();
        } catch (IOException e) {
            throw new CMSException("can't process mime object to create signature.", e);
        } catch (OperatorCreationException e) {
            throw new CMSException("can't create digest calculator: " + e.getMessage(), e);
        }

        // RFC 3852 11.1 Check the content-type attribute is correct
        {
            ASN1Primitive validContentType = getSingleValuedSignedAttribute(
                    CMSAttributes.contentType, "content-type");
            if (validContentType == null) {
                if (!isCounterSignature && signedAttributeSet != null) {
                    throw new CMSException("The content-type attribute type MUST be present whenever signed attributes are present in signed-data");
                }
            } else {
                if (isCounterSignature) {
                    throw new CMSException("[For counter signatures,] the signedAttributes field MUST NOT contain a content-type attribute");
                }

                if (!(validContentType instanceof ASN1ObjectIdentifier)) {
                    throw new CMSException("content-type attribute value not of ASN.1 type 'OBJECT IDENTIFIER'");
                }

                ASN1ObjectIdentifier signedContentType = (ASN1ObjectIdentifier) validContentType;

                if (!signedContentType.equals(contentType)) {
                    throw new CMSException("content-type attribute value does not match eContentType");
                }
            }
        }

        AttributeTable signedAttrTable = this.getSignedAttributes();

        // RFC 6211 Validate Algorithm Identifier protection attribute if present
        {
            AttributeTable unsignedAttrTable = this.getUnsignedAttributes();
            if (unsignedAttrTable != null && unsignedAttrTable.getAll(CMSAttributes.cmsAlgorithmProtect).size() > 0) {
                throw new CMSException("A cmsAlgorithmProtect attribute MUST be a signed attribute");
            }
            if (signedAttrTable != null) {
                ASN1EncodableVector protectionAttributes = signedAttrTable.getAll(CMSAttributes.cmsAlgorithmProtect);
                if (protectionAttributes.size() > 1) {
                    throw new CMSException("Only one instance of a cmsAlgorithmProtect attribute can be present");
                }

                if (protectionAttributes.size() > 0) {
                    Attribute attr = Attribute.getInstance(protectionAttributes.get(0));
                    if (attr.getAttrValues().size() != 1) {
                        throw new CMSException("A cmsAlgorithmProtect attribute MUST contain exactly one value");
                    }

                    CMSAlgorithmProtection algorithmProtection = CMSAlgorithmProtection.getInstance(attr.getAttributeValues()[0]);

                    if (!CMSUtils.isEquivalent(algorithmProtection.getDigestAlgorithm(), info.getDigestAlgorithm())) {
                        throw new CMSException("CMS Algorithm Identifier Protection check failed for digestAlgorithm");
                    }

                    if (!CMSUtils.isEquivalent(algorithmProtection.getSignatureAlgorithm(), info.getDigestEncryptionAlgorithm())) {
                        throw new CMSException("CMS Algorithm Identifier Protection check failed for signatureAlgorithm");
                    }
                }
            }
        }

        // RFC 3852 11.2 Check the message-digest attribute is correct
        {
            ASN1Primitive validMessageDigest = getSingleValuedSignedAttribute(
                    CMSAttributes.messageDigest, "message-digest");
            if (validMessageDigest == null) {
                if (signedAttributeSet != null) {
                    throw new CMSException("the message-digest signed attribute type MUST be present when there are any signed attributes present");
                }
            } else {
                if (!(validMessageDigest instanceof ASN1OctetString)) {
                    throw new CMSException("message-digest attribute value not of ASN.1 type 'OCTET STRING'");
                }

                ASN1OctetString signedMessageDigest = (ASN1OctetString) validMessageDigest;

                if (!Arrays.constantTimeAreEqual(resultDigest, signedMessageDigest.getOctets())) {
                    throw new CMSSignerDigestMismatchException("message-digest attribute value does not match calculated value");
                }
            }
        }

        // RFC 3852 11.4 Validate countersignature attribute(s)
        {
            if (signedAttrTable != null
                    && signedAttrTable.getAll(CMSAttributes.counterSignature).size() > 0) {
                throw new CMSException("A countersignature attribute MUST NOT be a signed attribute");
            }

            AttributeTable unsignedAttrTable = this.getUnsignedAttributes();
            if (unsignedAttrTable != null) {
                ASN1EncodableVector csAttrs = unsignedAttrTable.getAll(CMSAttributes.counterSignature);
                for (int i = 0; i < csAttrs.size(); ++i) {
                    Attribute csAttr = Attribute.getInstance(csAttrs.get(i));
                    if (csAttr.getAttrValues().size() < 1) {
                        throw new CMSException("A countersignature attribute MUST contain at least one AttributeValue");
                    }

                    // Note: We don't recursively validate the countersignature value
                }
            }
        }

        try {
            if (signedAttributeSet == null && resultDigest != null) {
                if (contentVerifier instanceof RawContentVerifier) {
                    RawContentVerifier rawVerifier = (RawContentVerifier) contentVerifier;
                    if (encName.equals("RSA")) {
                        DigestInfo digInfo = new DigestInfo(new AlgorithmIdentifier(digestAlgorithm.getAlgorithm(), DERNull.INSTANCE), resultDigest);
                        return rawVerifier.verify(digInfo.getEncoded(ASN1Encoding.DER), this.getSignature());
                    }

                    return rawVerifier.verify(resultDigest, this.getSignature());
                }
            }

            return contentVerifier.verify(this.getSignature());
        } catch (IOException e) {
            throw new CMSException("can't process mime object to create signature.", e);
        }
    }

    /**
     * Verify that the given verifier can successfully verify the signature on
     * this SignerInformation object.
     *
     * @param verifier a suitably configured SignerInformationVerifier.
     * @return true if the signer information is verified, false otherwise.
     * @throws org.spongycastle.cms.CMSVerifierCertificateNotValidException if the provider has an associated certificate and the certificate is not valid at the time given as the SignerInfo's signing time.
     * @throws org.spongycastle.cms.CMSException                            if the verifier is unable to create a ContentVerifiers or DigestCalculators.
     */
    public boolean verify(SignerInformationVerifier verifier)
            throws CMSException {
        Time signingTime = getSigningTime();   // has to be validated if present.

        if (verifier.hasAssociatedCertificate()) {
            if (signingTime != null) {
                X509CertificateHolder dcv = verifier.getAssociatedCertificate();

                if (!dcv.isValidOn(signingTime.getDate())) {
                    throw new CMSVerifierCertificateNotValidException("verifier not valid at signingTime");
                }
            }
        }

        return doVerify(verifier);
    }

    /**
     * Return the underlying ASN.1 object defining this SignerInformation object.
     *
     * @return a SignerInfo.
     */
    public SignerInfo toASN1Structure() {
        return info;
    }

    private ASN1Primitive getSingleValuedSignedAttribute(
            ASN1ObjectIdentifier attrOID, String printableName)
            throws CMSException {
        AttributeTable unsignedAttrTable = this.getUnsignedAttributes();
        if (unsignedAttrTable != null
                && unsignedAttrTable.getAll(attrOID).size() > 0) {
            throw new CMSException("The " + printableName
                    + " attribute MUST NOT be an unsigned attribute");
        }

        AttributeTable signedAttrTable = this.getSignedAttributes();
        if (signedAttrTable == null) {
            return null;
        }

        ASN1EncodableVector v = signedAttrTable.getAll(attrOID);
        switch (v.size()) {
            case 0:
                return null;
            case 1: {
                Attribute t = (Attribute) v.get(0);
                ASN1Set attrValues = t.getAttrValues();
                if (attrValues.size() != 1) {
                    throw new CMSException("A " + printableName
                            + " attribute MUST have a single attribute value");
                }

                return attrValues.getObjectAt(0).toASN1Primitive();
            }
            default:
                throw new CMSException("The SignedAttributes in a signerInfo MUST NOT include multiple instances of the "
                        + printableName + " attribute");
        }
    }

    private Time getSigningTime() throws CMSException {
        ASN1Primitive validSigningTime = getSingleValuedSignedAttribute(
                CMSAttributes.signingTime, "signing-time");

        if (validSigningTime == null) {
            return null;
        }

        try {
            return Time.getInstance(validSigningTime);
        } catch (IllegalArgumentException e) {
            throw new CMSException("signing-time attribute value not a valid 'Time' structure");
        }
    }
}