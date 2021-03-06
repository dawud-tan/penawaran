package org.spongycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * An indefinite-length encoding version of an ASN.1 ApplicationSpecific object.
 */
public class BERApplicationSpecific
        extends ASN1ApplicationSpecific {


    /**
     * Create an application specific object which is marked as constructed
     *
     * @param tagNo the tag number for this object.
     * @param vec   the objects making up the application specific object.
     */
    public BERApplicationSpecific(int tagNo, ASN1EncodableVector vec) {
        super(true, tagNo, getEncodedVector(vec));
    }

    private static byte[] getEncodedVector(ASN1EncodableVector vec) {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        for (int i = 0; i != vec.size(); i++) {
            try {
                bOut.write(((ASN1Object) vec.get(i)).getEncoded(ASN1Encoding.BER));
            } catch (IOException e) {
                throw new ASN1ParsingException("malformed object: " + e, e);
            }
        }
        return bOut.toByteArray();
    }

    /* (non-Javadoc)
     * @see org.spongycastle.asn1.ASN1Primitive#encode(org.spongycastle.asn1.DEROutputStream)
     */
    void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        int flags = BERTags.APPLICATION;
        if (isConstructed) {
            flags |= BERTags.CONSTRUCTED;
        }

        out.writeEncodedIndef(withTag, flags, tag, octets);
    }
}
