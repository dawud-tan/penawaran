package org.spongycastle.asn1;

import java.io.IOException;

/**
 * A DER encoding version of an application specific object.
 */
public class DLApplicationSpecific
        extends ASN1ApplicationSpecific {
    DLApplicationSpecific(
            boolean isConstructed,
            int tag,
            byte[] octets) {
        super(isConstructed, tag, octets);
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
}
