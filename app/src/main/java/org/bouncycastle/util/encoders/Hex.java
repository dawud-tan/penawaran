package org.bouncycastle.util.encoders;

import org.bouncycastle.util.Strings;

import java.io.ByteArrayOutputStream;

/**
 * Utility class for converting hex data to bytes and back again.
 */
public class Hex {
    private static final HexEncoder encoder = new HexEncoder();

    public static String toHexString(
            byte[] data) {
        return toHexString(data, 0, data.length);
    }

    public static String toHexString(
            byte[] data,
            int off,
            int length) {
        byte[] encoded = encode(data, off, length);
        return Strings.fromByteArray(encoded);
    }

    /**
     * encode the input data producing a Hex encoded byte array.
     *
     * @return a byte array containing the Hex encoded data.
     */
    public static byte[] encode(
            byte[] data) {
        return encode(data, 0, data.length);
    }

    /**
     * encode the input data producing a Hex encoded byte array.
     *
     * @return a byte array containing the Hex encoded data.
     */
    public static byte[] encode(
            byte[] data,
            int off,
            int length) {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        try {
            encoder.encode(data, off, length, bOut);
        } catch (Exception e) {
            throw new EncoderException("exception encoding Hex string: " + e.getMessage(), e);
        }

        return bOut.toByteArray();
    }


    /**
     * decode the Hex encoded String data - whitespace will be ignored.
     *
     * @return a byte array representing the decoded data.
     */
    public static byte[] decode(
            String data) {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        try {
            encoder.decode(data, bOut);
        } catch (Exception e) {
            throw new DecoderException("exception decoding Hex string: " + e.getMessage(), e);
        }

        return bOut.toByteArray();
    }

    /**
     * Decode the hexadecimal-encoded string strictly i.e. any non-hexadecimal characters will be
     * considered an error.
     *
     * @return a byte array representing the decoded data.
     */
    public static byte[] decodeStrict(String str, int off, int len) {
        try {
            return encoder.decodeStrict(str, off, len);
        } catch (Exception e) {
            throw new DecoderException("exception decoding Hex string: " + e.getMessage(), e);
        }
    }
}