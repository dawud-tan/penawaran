package org.spongycastle.asn1;

import org.spongycastle.util.Arrays;
import org.spongycastle.util.encoders.Hex;

import java.io.IOException;

/**
 * Base class for an ASN.1 ApplicationSpecific object
 */
public abstract class ASN1ApplicationSpecific
        extends ASN1Primitive {
    protected final boolean isConstructed;
    protected final int tag;
    protected final byte[] octets;

    ASN1ApplicationSpecific(
            boolean isConstructed,
            int tag,
            byte[] octets) {
        this.isConstructed = isConstructed;
        this.tag = tag;
        this.octets = Arrays.clone(octets);
    }

    /**
     * Return true if the object is marked as constructed, false otherwise.
     *
     * @return true if constructed, otherwise false.
     */
    public boolean isConstructed() {
        return isConstructed;
    }

    /**
     * Return the tag number associated with this object,
     *
     * @return the application tag number.
     */
    public int getApplicationTag() {
        return tag;
    }

    int encodedLength()
            throws IOException {
        return StreamUtil.calculateTagLength(tag) + StreamUtil.calculateBodyLength(octets.length) + octets.length;
    }

    /* (non-Javadoc)
     * @see org.spongycastle.asn1.ASN1Primitive#encode(org.spongycastle.asn1.DEROutputStream)
     */
    void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        int flags = BERTags.APPLICATION;
        if (isConstructed) {
            flags |= BERTags.CONSTRUCTED;
        }

        out.writeEncoded(withTag, flags, tag, octets);
    }

    boolean asn1Equals(
            ASN1Primitive o) {
        if (!(o instanceof ASN1ApplicationSpecific)) {
            return false;
        }

        ASN1ApplicationSpecific other = (ASN1ApplicationSpecific) o;

        return isConstructed == other.isConstructed
                && tag == other.tag
                && Arrays.areEqual(octets, other.octets);
    }

    public int hashCode() {
        return (isConstructed ? 1 : 0) ^ tag ^ Arrays.hashCode(octets);
    }

    private byte[] replaceTagNumber(int newTag, byte[] input)
            throws IOException {
        int tagNo = input[0] & 0x1f;
        int index = 1;
        //
        // with tagged object tag number is bottom 5 bits, or stored at the start of the content
        //
        if (tagNo == 0x1f) {
            int b = input[index++] & 0xff;

            // X.690-0207 8.1.2.4.2
            // "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
            if ((b & 0x7f) == 0) // Note: -1 will pass
            {
                throw new IOException("corrupted stream - invalid high tag number found");
            }

            while ((b & 0x80) != 0) {
                b = input[index++] & 0xff;
            }
        }

        byte[] tmp = new byte[input.length - index + 1];

        System.arraycopy(input, index, tmp, 1, tmp.length - 1);

        tmp[0] = (byte) newTag;

        return tmp;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append("[");
        if (isConstructed()) {
            sb.append("CONSTRUCTED ");
        }
        sb.append("APPLICATION ");
        sb.append(getApplicationTag());
        sb.append("]");
        // @todo content encoding somehow?
        if (this.octets != null) {
            sb.append(" #");
            sb.append(Hex.toHexString(this.octets));
        } else {
            sb.append(" #null");
        }
        sb.append(" ");
        return sb.toString();
    }
}
