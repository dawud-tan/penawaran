package org.spongycastle.cms;

import org.spongycastle.asn1.cms.IssuerAndSerialNumber;
import org.spongycastle.asn1.cms.SignerIdentifier;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.DigestCalculatorProvider;
import org.spongycastle.operator.OperatorCreationException;

/**
 * Builder for SignerInfo generator objects.
 */
public class SignerInfoGeneratorBuilder {
    private DigestCalculatorProvider digestProvider;
    private boolean directSignature;
    private CMSAttributeTableGenerator signedGen;
    private CMSAttributeTableGenerator unsignedGen;
    private CMSSignatureEncryptionAlgorithmFinder sigEncAlgFinder;

    /**
     * Base constructor.
     *
     * @param digestProvider a provider of digest calculators for the algorithms required in the signature and attribute calculations.
     */
    public SignerInfoGeneratorBuilder(DigestCalculatorProvider digestProvider) {
        this(digestProvider, new DefaultCMSSignatureEncryptionAlgorithmFinder());
    }

    /**
     * Base constructor with a particular finder for signature algorithms.
     *
     * @param digestProvider  a provider of digest calculators for the algorithms required in the signature and attribute calculations.
     * @param sigEncAlgFinder finder for algorithm IDs to store for the signature encryption/signature algorithm field.
     */
    public SignerInfoGeneratorBuilder(DigestCalculatorProvider digestProvider, CMSSignatureEncryptionAlgorithmFinder sigEncAlgFinder) {
        this.digestProvider = digestProvider;
        this.sigEncAlgFinder = sigEncAlgFinder;
    }

    /**
     * Build a generator with the passed in certHolder issuer and serial number as the signerIdentifier.
     *
     * @param contentSigner operator for generating the final signature in the SignerInfo with.
     * @param certHolder    carrier for the X.509 certificate related to the contentSigner.
     * @return a SignerInfoGenerator
     * @throws OperatorCreationException if the generator cannot be built.
     */
    public SignerInfoGenerator build(ContentSigner contentSigner, X509CertificateHolder certHolder)
            throws OperatorCreationException {
        SignerIdentifier sigId = new SignerIdentifier(new IssuerAndSerialNumber(certHolder.toASN1Structure()));

        SignerInfoGenerator sigInfoGen = createGenerator(contentSigner, sigId);

        sigInfoGen.setAssociatedCertificate(certHolder);

        return sigInfoGen;
    }


    private SignerInfoGenerator createGenerator(ContentSigner contentSigner, SignerIdentifier sigId)
            throws OperatorCreationException {
        if (directSignature) {
            return new SignerInfoGenerator(sigId, contentSigner, digestProvider, sigEncAlgFinder, true);
        }

        if (signedGen != null || unsignedGen != null) {
            if (signedGen == null) {
                signedGen = new DefaultSignedAttributeTableGenerator();
            }

            return new SignerInfoGenerator(sigId, contentSigner, digestProvider, sigEncAlgFinder, signedGen, unsignedGen);
        }

        return new SignerInfoGenerator(sigId, contentSigner, digestProvider, sigEncAlgFinder);
    }
}