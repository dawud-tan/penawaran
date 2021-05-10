package org.spongycastle.cms;

import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.ASN1Set;
import org.spongycastle.asn1.cms.ContentInfo;
import org.spongycastle.asn1.cms.SignedData;
import org.spongycastle.asn1.cms.SignerInfo;
import org.spongycastle.util.Encodable;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * general class for handling a pkcs7-signature message.
 * <p>
 * A simple example of usage - note, in the example below the validity of
 * the certificate isn't verified, just the fact that one of the certs
 * matches the given signer...
 *
 * <pre>
 *  Store                   certStore = s.getCertificates();
 *  SignerInformationStore  signers = s.getSignerInfos();
 *  Collection              c = signers.getSigners();
 *  Iterator                it = c.iterator();
 *
 *  while (it.hasNext())
 *  {
 *      SignerInformation   signer = (SignerInformation)it.next();
 *      Collection          certCollection = certStore.getMatches(signer.getSID());
 *
 *      Iterator              certIt = certCollection.iterator();
 *      X509CertificateHolder cert = (X509CertificateHolder)certIt.next();
 *
 *      if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC25519").build(cert)))
 *      {
 *          verified++;
 *      }
 *  }
 * </pre>
 */
public class CMSSignedData
        implements Encodable {
    private static final CMSSignedHelper HELPER = CMSSignedHelper.INSTANCE;

    SignedData signedData;
    ContentInfo contentInfo;
    CMSTypedData signedContent;
    SignerInformationStore signerInfoStore;

    private Map hashes;

    /**
     * base constructor - content with detached signature.
     *
     * @param signedContent the content that was signed.
     * @param sigData       the signature object.
     */
    public CMSSignedData(
            CMSProcessable signedContent,
            InputStream sigData)
            throws CMSException {
        this(signedContent, CMSUtils.readContentInfo(new ASN1InputStream(sigData)));
    }

    public CMSSignedData(
            final CMSProcessable signedContent,
            ContentInfo sigData)
            throws CMSException {
        if (signedContent instanceof CMSTypedData) {
            this.signedContent = (CMSTypedData) signedContent;
        } else {
            this.signedContent = new CMSTypedData() {

                public void write(OutputStream out)
                        throws IOException, CMSException {
                    signedContent.write(out);
                }

                public Object getContent() {
                    return signedContent.getContent();
                }
            };
        }

        this.contentInfo = sigData;
        this.signedData = getSignedData();
    }


    private SignedData getSignedData()
            throws CMSException {
        try {
            return SignedData.getInstance(contentInfo.getContent());
        } catch (ClassCastException e) {
            throw new CMSException("Malformed content.", e);
        } catch (IllegalArgumentException e) {
            throw new CMSException("Malformed content.", e);
        }
    }

    /**
     * return the collection of signers that are associated with the
     * signatures for the message.
     */
    public SignerInformationStore getSignerInfos() {
        if (signerInfoStore == null) {
            ASN1Set s = signedData.getSignerInfos();
            List signerInfos = new ArrayList();

            for (int i = 0; i != s.size(); i++) {
                SignerInfo info = SignerInfo.getInstance(s.getObjectAt(i));
                ASN1ObjectIdentifier contentType = signedData.getEncapContentInfo().getContentType();

                if (hashes == null) {
                    signerInfos.add(new SignerInformation(info, contentType, signedContent, null));
                } else {
                    Object obj = hashes.keySet().iterator().next();
                    byte[] hash = (obj instanceof String) ? (byte[]) hashes.get(info.getDigestAlgorithm().getAlgorithm().getId()) : (byte[]) hashes.get(info.getDigestAlgorithm().getAlgorithm());

                    signerInfos.add(new SignerInformation(info, contentType, null, hash));
                }
            }

            signerInfoStore = new SignerInformationStore(signerInfos);
        }

        return signerInfoStore;
    }

}