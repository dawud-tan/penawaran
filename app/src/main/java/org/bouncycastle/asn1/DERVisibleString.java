package org.bouncycastle.asn1;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

import java.io.IOException;

/**
 * DER VisibleString object encoding ISO 646 (ASCII) character code points 32 to 126.
 * <p>
 * Explicit character set escape sequences are not allowed.
 * </p>
 */
public class DERVisibleString
        extends ASN1Primitive
        implements ASN1String {
    private final byte[] string;

    /**
     * Return a Visible String from the passed in object.
     *
     * @param obj a DERVisibleString or an object that can be converted into one.
     * @return a DERVisibleString instance, or null
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static DERVisibleString getInstance(
            Object obj) {
        if (obj == null || obj instanceof DERVisibleString) {
            return (DERVisibleString) obj;
        }

        if (obj instanceof byte[]) {
            try {
                return (DERVisibleString) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /*
     * Basic constructor - byte encoded string.
     */
    DERVisibleString(
            byte[] string) {
        this.string = string;
    }


    public String getString() {
        return Strings.fromByteArray(string);
    }

    public String toString() {
        return getString();
    }


    boolean isConstructed() {
        return false;
    }

    int encodedLength() {
        return 1 + StreamUtil.calculateBodyLength(string.length) + string.length;
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        out.writeEncoded(withTag, BERTags.VISIBLE_STRING, this.string);
    }

    boolean asn1Equals(
            ASN1Primitive o) {
        if (!(o instanceof DERVisibleString)) {
            return false;
        }

        return Arrays.areEqual(string, ((DERVisibleString) o).string);
    }

    public int hashCode() {
        return Arrays.hashCode(string);
    }
}
