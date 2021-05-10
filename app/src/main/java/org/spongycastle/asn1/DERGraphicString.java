package org.spongycastle.asn1;

import org.spongycastle.util.Arrays;
import org.spongycastle.util.Strings;

import java.io.IOException;

public class DERGraphicString
        extends ASN1Primitive
        implements ASN1String {
    private final byte[] string;

    /**
     * return a Graphic String from the passed in object
     *
     * @param obj a DERGraphicString or an object that can be converted into one.
     * @return a DERGraphicString instance, or null.
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static DERGraphicString getInstance(
            Object obj) {
        if (obj == null || obj instanceof DERGraphicString) {
            return (DERGraphicString) obj;
        }

        if (obj instanceof byte[]) {
            try {
                return (DERGraphicString) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }


    /**
     * basic constructor - with bytes.
     *
     * @param string the byte encoding of the characters making up the string.
     */
    public DERGraphicString(
            byte[] string) {
        this.string = Arrays.clone(string);
    }


    boolean isConstructed() {
        return false;
    }

    int encodedLength() {
        return 1 + StreamUtil.calculateBodyLength(string.length) + string.length;
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        out.writeEncoded(withTag, BERTags.GRAPHIC_STRING, string);
    }

    public int hashCode() {
        return Arrays.hashCode(string);
    }

    boolean asn1Equals(
            ASN1Primitive o) {
        if (!(o instanceof DERGraphicString)) {
            return false;
        }

        DERGraphicString s = (DERGraphicString) o;

        return Arrays.areEqual(string, s.string);
    }

    public String getString() {
        return Strings.fromByteArray(string);
    }
}
