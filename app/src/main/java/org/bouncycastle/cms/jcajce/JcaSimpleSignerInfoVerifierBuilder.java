package org.bouncycastle.cms.jcajce;

import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.security.PublicKey;

public class JcaSimpleSignerInfoVerifierBuilder {
    private Helper helper = new Helper();

    public SignerInformationVerifier build(PublicKey pubKey)
            throws OperatorCreationException {
        return new SignerInformationVerifier(new DefaultCMSSignatureAlgorithmNameGenerator(), new DefaultSignatureAlgorithmIdentifierFinder(), helper.createContentVerifierProvider(pubKey), helper.createDigestCalculatorProvider());
    }

    private class Helper {
        ContentVerifierProvider createContentVerifierProvider(PublicKey publicKey)
                throws OperatorCreationException {
            return new JcaContentVerifierProviderBuilder().build(publicKey);
        }


        DigestCalculatorProvider createDigestCalculatorProvider()
                throws OperatorCreationException {
            return new JcaDigestCalculatorProviderBuilder().build();
        }
    }
}