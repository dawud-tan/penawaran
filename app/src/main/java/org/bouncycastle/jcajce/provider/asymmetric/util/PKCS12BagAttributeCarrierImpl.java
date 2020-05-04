package org.bouncycastle.jcajce.provider.asymmetric.util;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

public class PKCS12BagAttributeCarrierImpl {
    private Hashtable pkcs12Attributes;
    private Vector pkcs12Ordering;


    public void setBagAttribute(
            ASN1ObjectIdentifier oid,
            ASN1Encodable attribute) {
        if (pkcs12Attributes.containsKey(oid)) {                           // preserve original ordering
            pkcs12Attributes.put(oid, attribute);
        } else {
            pkcs12Attributes.put(oid, attribute);
            pkcs12Ordering.addElement(oid);
        }
    }

    public ASN1Encodable getBagAttribute(
            ASN1ObjectIdentifier oid) {
        return (ASN1Encodable) pkcs12Attributes.get(oid);
    }

    public Enumeration getBagAttributeKeys() {
        return pkcs12Ordering.elements();
    }


}