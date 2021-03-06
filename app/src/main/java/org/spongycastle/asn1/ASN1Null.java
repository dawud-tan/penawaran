/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.spongycastle.asn1;

import java.io.IOException;

/**
 * A NULL object - use DERNull.INSTANCE for populating structures.
 */
public abstract class ASN1Null
        extends ASN1Primitive {
    ASN1Null() {

    }

    public int hashCode() {
        return -1;
    }

    boolean asn1Equals(
            ASN1Primitive o) {
        return o instanceof ASN1Null;
    }

    abstract void encode(ASN1OutputStream out, boolean withTag) throws IOException;

    public String toString() {
        return "NULL";
    }
}
