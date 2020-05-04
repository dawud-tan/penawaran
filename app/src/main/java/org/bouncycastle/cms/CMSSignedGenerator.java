package org.bouncycastle.cms;

import org.bouncycastle.util.Store;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class CMSSignedGenerator {

    protected List certs = new ArrayList();
    protected List crls = new ArrayList();
    protected List _signers = new ArrayList();
    protected List signerGens = new ArrayList();
    protected Map digests = new HashMap();

    /**
     * base constructor
     */
    protected CMSSignedGenerator() {
    }


    /**
     * Add the certificates in certStore to the certificate set to be included with the generated SignedData message.
     *
     * @param certStore the store containing the certificates to be included.
     * @throws CMSException if the certificates cannot be encoded for adding.
     */
    public void addCertificates(
            Store certStore)
            throws CMSException {
        certs.addAll(CMSUtils.getCertificatesFromStore(certStore));
    }


    /**
     * Add the CRLs in crlStore to the CRL set to be included with the generated SignedData message.
     *
     * @param crlStore the store containing the CRLs to be included.
     * @throws CMSException if the CRLs cannot be encoded for adding.
     */
    public void addCRLs(
            Store crlStore)
            throws CMSException {
        crls.addAll(CMSUtils.getCRLsFromStore(crlStore));
    }


    /**
     * Add the attribute certificates in attrStore to the certificate set to be included with the generated SignedData message.
     *
     * @param attrStore the store containing the certificates to be included.
     * @throws CMSException if the attribute certificate cannot be encoded for adding.
     */
    public void addAttributeCertificates(
            Store attrStore)
            throws CMSException {
        certs.addAll(CMSUtils.getAttributeCertificatesFromStore(attrStore));
    }

    /**
     * Add a store of pre-calculated signers to the generator.
     *
     * @param signerStore store of signers
     */
    public void addSigners(
            SignerInformationStore signerStore) {
        Iterator it = signerStore.getSigners().iterator();

        while (it.hasNext()) {
            _signers.add(it.next());
        }
    }

    /**
     * Add a generator for a particular signer to this CMS SignedData generator.
     *
     * @param infoGen the generator representing the particular signer.
     */
    public void addSignerInfoGenerator(SignerInfoGenerator infoGen) {
        signerGens.add(infoGen);
    }
}