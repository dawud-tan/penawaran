package org.spongycastle.asn1;

import org.spongycastle.util.Arrays;
import org.spongycastle.util.Strings;

import java.io.IOException;

/**
 * DER NumericString object - this is an ascii string of characters {0,1,2,3,4,5,6,7,8,9, }.
 * ASN.1 NUMERIC-STRING object.
 * <p>
 * This is an ASCII string of characters {0,1,2,3,4,5,6,7,8,9} + space.
 * <p>
 * See X.680 section 37.2.
 * <p>
 * Explicit character set escape sequences are not allowed.
 */
public class DERNumericString
        extends ASN1Primitive
        implements ASN1String {
    private final byte[] string;

    /**
     * Return a Numeric string from the passed in object
     *
     * @param obj a DERNumericString or an object that can be converted into one.
     * @return a DERNumericString instance, or null
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static DERNumericString getInstance(
            Object obj) {
        if (obj == null || obj instanceof DERNumericString) {
            return (DERNumericString) obj;
        }

        if (obj instanceof byte[]) {
            try {
                return (DERNumericString) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Basic constructor - with bytes.
     */
    DERNumericString(
            byte[] string) {
        this.string = string;
    }

    /**
     * Constructor with optional validation.
     *
     * @param string   the base string to wrap.
     * @param validate whether or not to check the string.
     * @throws IllegalArgumentException if validate is true and the string
     *                                  contains characters that should not be in a NumericString.
     */
    public DERNumericString(
            String string,
            boolean validate) {
        if (validate && !isNumericString(string)) {
            throw new IllegalArgumentException("string contains illegal characters");
        }

        this.string = Strings.toByteArray(string);
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
        out.writeEncoded(withTag, BERTags.NUMERIC_STRING, string);
    }

    public int hashCode() {
        return Arrays.hashCode(string);
    }

    boolean asn1Equals(
            ASN1Primitive o) {
        if (!(o instanceof DERNumericString)) {
            return false;
        }

        DERNumericString s = (DERNumericString) o;

        return Arrays.areEqual(string, s.string);
    }

    /**
     * Return true if the string can be represented as a NumericString ('0'..'9', ' ')
     *
     * @param str string to validate.
     * @return true if numeric, fale otherwise.
     */
    public static boolean isNumericString(
            String str) {
        for (int i = str.length() - 1; i >= 0; i--) {
            char ch = str.charAt(i);

            if (ch > 0x007f) {
                return false;
            }

            if (('0' <= ch && ch <= '9') || ch == ' ') {
                continue;
            }

            return false;
        }

        return true;
    }
}
