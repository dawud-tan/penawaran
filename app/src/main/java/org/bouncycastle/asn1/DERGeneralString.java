package org.bouncycastle.asn1;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

import java.io.IOException;

/**
 * ASN.1 GENERAL-STRING data type.
 * <p>
 * This is an 8-bit encoded ISO 646 (ASCII) character set
 * with optional escapes to other character sets.
 * </p>
 */
public class DERGeneralString
        extends ASN1Primitive
        implements ASN1String {
    private final byte[] string;

    /**
     * Return a GeneralString from the given object.
     *
     * @param obj the object we want converted.
     * @return a DERBMPString instance, or null.
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static DERGeneralString getInstance(
            Object obj) {
        if (obj == null || obj instanceof DERGeneralString) {
            return (DERGeneralString) obj;
        }

        if (obj instanceof byte[]) {
            try {
                return (DERGeneralString) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: "
                + obj.getClass().getName());
    }


    DERGeneralString(byte[] string) {
        this.string = string;
    }


    /**
     * Return a Java String representation of our contained String.
     *
     * @return a Java String representing our contents.
     */
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
        out.writeEncoded(withTag, BERTags.GENERAL_STRING, string);
    }

    public int hashCode() {
        return Arrays.hashCode(string);
    }

    boolean asn1Equals(ASN1Primitive o) {
        if (!(o instanceof DERGeneralString)) {
            return false;
        }
        DERGeneralString s = (DERGeneralString) o;

        return Arrays.areEqual(string, s.string);
    }
}
