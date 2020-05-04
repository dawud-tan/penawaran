package org.bouncycastle.asn1;

import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.math.BigInteger;

/**
 * Class representing the ASN.1 ENUMERATED type.
 */
public class ASN1Enumerated
        extends ASN1Primitive {
    private final byte[] bytes;
    private final int start;

    /**
     * return an enumerated from the passed in object
     *
     * @param obj an ASN1Enumerated or an object that can be converted into one.
     * @return an ASN1Enumerated instance, or null.
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static ASN1Enumerated getInstance(
            Object obj) {
        if (obj == null || obj instanceof ASN1Enumerated) {
            return (ASN1Enumerated) obj;
        }

        if (obj instanceof byte[]) {
            try {
                return (ASN1Enumerated) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Constructor from int.
     *
     * @param value the value of this enumerated.
     */
    public ASN1Enumerated(int value) {
        if (value < 0) {
            throw new IllegalArgumentException("enumerated must be non-negative");
        }

        this.bytes = BigInteger.valueOf(value).toByteArray();
        this.start = 0;
    }

    /**
     * Constructor from BigInteger
     *
     * @param value the value of this enumerated.
     */
    public ASN1Enumerated(BigInteger value) {
        if (value.signum() < 0) {
            throw new IllegalArgumentException("enumerated must be non-negative");
        }

        this.bytes = value.toByteArray();
        this.start = 0;
    }

    /**
     * Constructor from encoded BigInteger.
     *
     * @param bytes the value of this enumerated as an encoded BigInteger (signed).
     */
    public ASN1Enumerated(byte[] bytes) {
        if (ASN1Integer.isMalformed(bytes)) {
            throw new IllegalArgumentException("malformed enumerated");
        }
        if (0 != (bytes[0] & 0x80)) {
            throw new IllegalArgumentException("enumerated must be non-negative");
        }

        this.bytes = Arrays.clone(bytes);
        this.start = ASN1Integer.signBytesToSkip(bytes);
    }


    boolean isConstructed() {
        return false;
    }

    int encodedLength() {
        return 1 + StreamUtil.calculateBodyLength(bytes.length) + bytes.length;
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        out.writeEncoded(withTag, BERTags.ENUMERATED, bytes);
    }

    boolean asn1Equals(
            ASN1Primitive o) {
        if (!(o instanceof ASN1Enumerated)) {
            return false;
        }

        ASN1Enumerated other = (ASN1Enumerated) o;

        return Arrays.areEqual(this.bytes, other.bytes);
    }

    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    private static ASN1Enumerated[] cache = new ASN1Enumerated[12];

    static ASN1Enumerated fromOctetString(byte[] enc) {
        if (enc.length > 1) {
            return new ASN1Enumerated(enc);
        }

        if (enc.length == 0) {
            throw new IllegalArgumentException("ENUMERATED has zero length");
        }
        int value = enc[0] & 0xff;

        if (value >= cache.length) {
            return new ASN1Enumerated(enc);
        }

        ASN1Enumerated possibleMatch = cache[value];

        if (possibleMatch == null) {
            possibleMatch = cache[value] = new ASN1Enumerated(enc);
        }

        return possibleMatch;
    }
}
