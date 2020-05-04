package org.bouncycastle.asn1.teletrust;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECParametersHolder;
import org.bouncycastle.util.Strings;

import java.util.Enumeration;
import java.util.Hashtable;

/**
 * Elliptic curves defined in "ECC Brainpool Standard Curves and Curve Generation"
 * http://www.ecc-brainpool.org/download/draft_pkix_additional_ecc_dp.txt
 */
public class TeleTrusTNamedCurves {


    static final Hashtable objIds = new Hashtable();
    static final Hashtable curves = new Hashtable();
    static final Hashtable names = new Hashtable();


    public static X9ECParameters getByName(
            String name) {
        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) objIds.get(Strings.toLowerCase(name));

        if (oid != null) {
            return getByOID(oid);
        }

        return null;
    }

    /**
     * return the X9ECParameters object for the named curve represented by
     * the passed in object identifier. Null if the curve isn't present.
     *
     * @param oid an object identifier representing a named curve, if present.
     */
    public static X9ECParameters getByOID(
            ASN1ObjectIdentifier oid) {
        X9ECParametersHolder holder = (X9ECParametersHolder) curves.get(oid);

        if (holder != null) {
            return holder.getParameters();
        }

        return null;
    }


    /**
     * returns an enumeration containing the name strings for curves
     * contained in this structure.
     */
    public static Enumeration getNames() {    // we need to use names so we get the mixed case names.
        return names.elements();
    }


}
