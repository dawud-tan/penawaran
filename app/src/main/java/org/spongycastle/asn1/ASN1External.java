package org.spongycastle.asn1;

import java.io.IOException;

/**
 * Class representing the DER-type External
 */
public abstract class ASN1External
        extends ASN1Primitive {
    protected ASN1ObjectIdentifier directReference;
    protected ASN1Integer indirectReference;
    protected ASN1Primitive dataValueDescriptor;
    protected int encoding;
    protected ASN1Primitive externalContent;

    /**
     * Construct an EXTERNAL object, the input encoding vector must have exactly two elements on it.
     * <p>
     * Acceptable input formats are:
     * <ul>
     * <li> {@link ASN1ObjectIdentifier} + data {@link DERTaggedObject} (direct reference form)</li>
     * <li> {@link ASN1Integer} + data {@link DERTaggedObject} (indirect reference form)</li>
     * <li> Anything but {@link DERTaggedObject} + data {@link DERTaggedObject} (data value form)</li>
     * </ul>
     *
     * @throws IllegalArgumentException if input size is wrong, or
     */
    public ASN1External(ASN1EncodableVector vector) {
        int offset = 0;

        ASN1Primitive enc = getObjFromVector(vector, offset);
        if (enc instanceof ASN1ObjectIdentifier) {
            directReference = (ASN1ObjectIdentifier) enc;
            offset++;
            enc = getObjFromVector(vector, offset);
        }
        if (enc instanceof ASN1Integer) {
            indirectReference = (ASN1Integer) enc;
            offset++;
            enc = getObjFromVector(vector, offset);
        }
        if (!(enc instanceof ASN1TaggedObject)) {
            dataValueDescriptor = enc;
            offset++;
            enc = getObjFromVector(vector, offset);
        }

        if (vector.size() != offset + 1) {
            throw new IllegalArgumentException("input vector too large");
        }

        if (!(enc instanceof ASN1TaggedObject)) {
            throw new IllegalArgumentException("No tagged object found in vector. Structure doesn't seem to be of type External");
        }
        ASN1TaggedObject obj = (ASN1TaggedObject) enc;
        setEncoding(obj.getTagNo());
        externalContent = obj.getObject();
    }

    private ASN1Primitive getObjFromVector(ASN1EncodableVector v, int index) {
        if (v.size() <= index) {
            throw new IllegalArgumentException("too few objects in input vector");
        }

        return v.get(index).toASN1Primitive();
    }


    /**
     * Creates a new instance of External.
     * See X.690 for more informations about the meaning of these parameters
     *
     * @param directReference     The direct reference or <code>null</code> if not set.
     * @param indirectReference   The indirect reference or <code>null</code> if not set.
     * @param dataValueDescriptor The data value descriptor or <code>null</code> if not set.
     * @param encoding            The encoding to be used for the external data
     * @param externalData        The external data
     */
    public ASN1External(ASN1ObjectIdentifier directReference, ASN1Integer indirectReference, ASN1Primitive dataValueDescriptor, int encoding, ASN1Primitive externalData) {
        setDirectReference(directReference);
        setIndirectReference(indirectReference);
        setDataValueDescriptor(dataValueDescriptor);
        setEncoding(encoding);
        setExternalContent(externalData.toASN1Primitive());
    }

    ASN1Primitive toDERObject() {
        return new DERExternal(directReference, indirectReference, dataValueDescriptor, encoding, externalContent);
    }

    ASN1Primitive toDLObject() {
        return new DLExternal(directReference, indirectReference, dataValueDescriptor, encoding, externalContent);
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
        int ret = 0;
        if (directReference != null) {
            ret = directReference.hashCode();
        }
        if (indirectReference != null) {
            ret ^= indirectReference.hashCode();
        }
        if (dataValueDescriptor != null) {
            ret ^= dataValueDescriptor.hashCode();
        }
        ret ^= externalContent.hashCode();
        return ret;
    }

    boolean isConstructed() {
        return true;
    }

    int encodedLength()
            throws IOException {
        return this.getEncoded().length;
    }

    /* (non-Javadoc)
     * @see org.spongycastle.asn1.ASN1Primitive#asn1Equals(org.spongycastle.asn1.ASN1Primitive)
     */
    boolean asn1Equals(ASN1Primitive o) {
        if (!(o instanceof ASN1External)) {
            return false;
        }
        if (this == o) {
            return true;
        }
        ASN1External other = (ASN1External) o;
        if (directReference != null) {
            if (other.directReference == null || !other.directReference.equals(directReference)) {
                return false;
            }
        }
        if (indirectReference != null) {
            if (other.indirectReference == null || !other.indirectReference.equals(indirectReference)) {
                return false;
            }
        }
        if (dataValueDescriptor != null) {
            if (other.dataValueDescriptor == null || !other.dataValueDescriptor.equals(dataValueDescriptor)) {
                return false;
            }
        }
        return externalContent.equals(other.externalContent);
    }

    /**
     * Sets the data value descriptor
     *
     * @param dataValueDescriptor The descriptor
     */
    private void setDataValueDescriptor(ASN1Primitive dataValueDescriptor) {
        this.dataValueDescriptor = dataValueDescriptor;
    }

    /**
     * Sets the direct reference of the external element
     *
     * @param directReferemce The reference
     */
    private void setDirectReference(ASN1ObjectIdentifier directReferemce) {
        this.directReference = directReferemce;
    }

    /**
     * Sets the encoding of the content. Valid values are
     * <ul>
     * <li><code>0</code> single-ASN1-type</li>
     * <li><code>1</code> OCTET STRING</li>
     * <li><code>2</code> BIT STRING</li>
     * </ul>
     *
     * @param encoding The encoding
     */
    private void setEncoding(int encoding) {
        if (encoding < 0 || encoding > 2) {
            throw new IllegalArgumentException("invalid encoding value: " + encoding);
        }
        this.encoding = encoding;
    }

    /**
     * Sets the content of this element
     *
     * @param externalContent The content
     */
    private void setExternalContent(ASN1Primitive externalContent) {
        this.externalContent = externalContent;
    }

    /**
     * Sets the indirect reference of this element
     *
     * @param indirectReference The reference
     */
    private void setIndirectReference(ASN1Integer indirectReference) {
        this.indirectReference = indirectReference;
    }
}
