package org.bouncycastle.asn1;

/**
 * DER UTC time object.
 */
public class DERUTCTime
        extends ASN1UTCTime {


    public DERUTCTime(String time) {
        super(time);
    }

    // TODO: create proper DER encoding.
}
