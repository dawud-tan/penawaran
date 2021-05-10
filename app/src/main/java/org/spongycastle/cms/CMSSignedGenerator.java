package org.spongycastle.cms;

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