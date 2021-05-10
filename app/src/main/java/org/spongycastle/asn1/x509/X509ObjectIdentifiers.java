package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1ObjectIdentifier;

public interface X509ObjectIdentifiers {

    /**
     * Subject RDN components: telephone_number = 2.5.4.20
     */
    ASN1ObjectIdentifier id_at_telephoneNumber = new ASN1ObjectIdentifier("2.5.4.20").intern();
    /**
     * Subject RDN components: name = 2.5.4.41
     */
    ASN1ObjectIdentifier id_at_name = new ASN1ObjectIdentifier("2.5.4.41").intern();

    ASN1ObjectIdentifier id_at_organizationIdentifier = new ASN1ObjectIdentifier("2.5.4.97").intern();

    /**
     * id-pkix OID: 1.3.6.1.5.5.7
     */
    ASN1ObjectIdentifier id_pkix = new ASN1ObjectIdentifier("1.3.6.1.5.5.7");

    /**
     * id-pkix OID:         1.3.6.1.5.5.7.48
     */
    ASN1ObjectIdentifier id_ad = id_pkix.branch("48");
    /**
     * id-ad-caIssuers OID: 1.3.6.1.5.5.7.48.2
     */
    ASN1ObjectIdentifier id_ad_caIssuers = id_ad.branch("2").intern();
    /**
     * id-ad-ocsp OID:      1.3.6.1.5.5.7.48.1
     */
    ASN1ObjectIdentifier id_ad_ocsp = id_ad.branch("1").intern();
}