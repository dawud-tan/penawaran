package org.bouncycastle.asn1;

import org.bouncycastle.util.Arrays;

import java.io.IOException;

/**
 * DER UniversalString object - encodes UNICODE (ISO 10646) characters using 32-bit format. In Java we
 * have no way of representing this directly so we rely on byte arrays to carry these.
 */
public class DERUniversalString
        extends ASN1Primitive
        implements ASN1String {
    private static final char[] table = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    private final byte[] string;

    /**
     * Return a Universal String from the passed in object.
     *
     * @param obj a DERUniversalString or an object that can be converted into one.
     * @return a DERUniversalString instance, or null
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static DERUniversalString getInstance(
            Object obj) {
        if (obj == null || obj instanceof DERUniversalString) {
            return (DERUniversalString) obj;
        }

        if (obj instanceof byte[]) {
            try {
                return (DERUniversalString) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Basic constructor - byte encoded string.
     *
     * @param string the byte encoding of the string to be carried in the UniversalString object,
     */
    public DERUniversalString(
            byte[] string) {
        this.string = Arrays.clone(string);
    }

    public String getString() {
        StringBuffer buf = new StringBuffer("#");

        byte[] string;
        try {
            string = getEncoded();
        } catch (IOException e) {
            throw new ASN1ParsingException("internal error encoding UniversalString");
        }

        for (int i = 0; i != string.length; i++) {
            buf.append(table[(string[i] >>> 4) & 0xf]);
            buf.append(table[string[i] & 0xf]);
        }

        return buf.toString();
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
        out.writeEncoded(withTag, BERTags.UNIVERSAL_STRING, string);
    }

    boolean asn1Equals(
            ASN1Primitive o) {
        if (!(o instanceof DERUniversalString)) {
            return false;
        }

        return Arrays.areEqual(string, ((DERUniversalString) o).string);
    }

    public int hashCode() {
        return Arrays.hashCode(string);
    }
}
