package org.bouncycastle.cms.jcajce;

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Use this class if you are using a provider that has all the facilities you
 * need.
 * <p>
 * For example:
 * <pre>
 *      CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
 *      ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC25519").build(signKP.getPrivate());
 *
 *      gen.addSignerInfoGenerator(
 *                new JcaSignerInfoGeneratorBuilder(
 *                     new JcaDigestCalculatorProviderBuilder().setProvider("BC25519").build())
 *                     .build(sha1Signer, signCert));
 * </pre>
 * becomes:
 * <pre>
 *      CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
 *
 *      gen.addSignerInfoGenerator(
 *                new JcaSimpleSignerInfoGeneratorBuilder()
 *                     .setProvider("BC25519")
 *                     .build("SHA1withRSA", signKP.getPrivate(), signCert));
 * </pre>
 */
public class JcaSimpleSignerInfoGeneratorBuilder {
    private Helper helper;

    public JcaSimpleSignerInfoGeneratorBuilder() {
        this.helper = new Helper();
    }

    public SignerInfoGenerator build(String algorithmName, PrivateKey privateKey, X509Certificate certificate)
            throws OperatorCreationException, CertificateEncodingException {
        privateKey = CMSUtils.cleanPrivateKey(privateKey);
        ContentSigner contentSigner = helper.createContentSigner(algorithmName, privateKey);

        return configureAndBuild().build(contentSigner, new JcaX509CertificateHolder(certificate));
    }

    private SignerInfoGeneratorBuilder configureAndBuild()
            throws OperatorCreationException {
        SignerInfoGeneratorBuilder infoGeneratorBuilder = new SignerInfoGeneratorBuilder(helper.createDigestCalculatorProvider());
        return infoGeneratorBuilder;
    }

    private class Helper {
        ContentSigner createContentSigner(String algorithm, PrivateKey privateKey)
                throws OperatorCreationException {
            privateKey = CMSUtils.cleanPrivateKey(privateKey);
            return new JcaContentSignerBuilder(algorithm).build(privateKey);
        }

        DigestCalculatorProvider createDigestCalculatorProvider()
                throws OperatorCreationException {
            return new JcaDigestCalculatorProviderBuilder().build();
        }
    }
}