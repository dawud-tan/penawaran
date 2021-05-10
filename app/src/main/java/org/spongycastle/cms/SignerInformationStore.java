package org.spongycastle.cms;

import org.spongycastle.util.Iterable;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class SignerInformationStore
        implements Iterable<SignerInformation> {
    private List all;
    private Map table = new HashMap();


    /**
     * Create a store containing a collection of SignerInformation objects.
     *
     * @param signerInfos a collection signer information objects to contain.
     */
    public SignerInformationStore(
            Collection<SignerInformation> signerInfos) {
        Iterator it = signerInfos.iterator();

        while (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            SignerId sid = signer.getSID();

            List list = (ArrayList) table.get(sid);
            if (list == null) {
                list = new ArrayList(1);
                table.put(sid, list);
            }

            list.add(signer);
        }

        this.all = new ArrayList(signerInfos);
    }


    /**
     * Return all signers in the collection
     *
     * @return a collection of signers.
     */
    public Collection<SignerInformation> getSigners() {
        return new ArrayList(all);
    }

    /**
     * Support method for Iterable where available.
     */
    public Iterator<SignerInformation> iterator() {
        return getSigners().iterator();
    }
}