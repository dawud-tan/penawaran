package org.bouncycastle.asn1;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

import java.io.IOException;

/**
 * DER T61String (also the teletex string), try not to use this if you don't need to. The standard support the encoding for
 * this has been withdrawn.
 */
public class DERT61String
        extends ASN1Primitive
        implements ASN1String {
    private byte[] string;

    /**
     * Return a T61 string from the passed in object.
     *
     * @param obj a DERT61String or an object that can be converted into one.
     * @return a DERT61String instance, or null
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static DERT61String getInstance(
            Object obj) {
        if (obj == null || obj instanceof DERT61String) {
            return (DERT61String) obj;
        }

        if (obj instanceof byte[]) {
            try {
                return (DERT61String) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }


    /**
     * Basic constructor - string encoded as a sequence of bytes.
     *
     * @param string the byte encoding of the string to be wrapped.
     */
    public DERT61String(
            byte[] string) {
        this.string = Arrays.clone(string);
    }


    /**
     * Decode the encoded string and return it, 8 bit encoding assumed.
     *
     * @return the decoded String
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
        out.writeEncoded(withTag, BERTags.T61_STRING, string);
    }

    /**
     * Return the encoded string as a byte array.
     *
     * @return the actual bytes making up the encoded body of the T61 string.
     */
    public byte[] getOctets() {
        return Arrays.clone(string);
    }

    boolean asn1Equals(
            ASN1Primitive o) {
        if (!(o instanceof DERT61String)) {
            return false;
        }

        return Arrays.areEqual(string, ((DERT61String) o).string);
    }

    public int hashCode() {
        return Arrays.hashCode(string);
    }
}
