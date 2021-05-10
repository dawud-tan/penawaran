package org.spongycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Class representing the DER-type External
 */
public class DERExternal
        extends ASN1External {
    /**
     * Creates a new instance of DERExternal.
     * See X.690 for more informations about the meaning of these parameters
     *
     * @param directReference     The direct reference or <code>null</code> if not set.
     * @param indirectReference   The indirect reference or <code>null</code> if not set.
     * @param dataValueDescriptor The data value descriptor or <code>null</code> if not set.
     * @param encoding            The encoding to be used for the external data
     * @param externalData        The external data
     */
    public DERExternal(ASN1ObjectIdentifier directReference, ASN1Integer indirectReference, ASN1Primitive dataValueDescriptor, int encoding, ASN1Primitive externalData) {
        super(directReference, indirectReference, dataValueDescriptor, encoding, externalData);
    }

    ASN1Primitive toDERObject() {
        return this;
    }

    ASN1Primitive toDLObject() {
        return this;
    }

    int encodedLength()
            throws IOException {
        return this.getEncoded().length;
    }

    /* (non-Javadoc)
     * @see org.spongycastle.asn1.ASN1Primitive#encode(org.spongycastle.asn1.DEROutputStream)
     */
    void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        if (directReference != null) {
            baos.write(directReference.getEncoded(ASN1Encoding.DER));
        }
        if (indirectReference != null) {
            baos.write(indirectReference.getEncoded(ASN1Encoding.DER));
        }
        if (dataValueDescriptor != null) {
            baos.write(dataValueDescriptor.getEncoded(ASN1Encoding.DER));
        }
        DERTaggedObject obj = new DERTaggedObject(true, encoding, externalContent);
        baos.write(obj.getEncoded(ASN1Encoding.DER));

        out.writeEncoded(withTag, BERTags.CONSTRUCTED, BERTags.EXTERNAL, baos.toByteArray());
    }
}
