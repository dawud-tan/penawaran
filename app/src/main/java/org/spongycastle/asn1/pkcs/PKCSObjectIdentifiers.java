package org.spongycastle.asn1.pkcs;

import org.spongycastle.asn1.ASN1ObjectIdentifier;

/**
 * pkcs-1 OBJECT IDENTIFIER ::=<p>
 * { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }
 */
public interface PKCSObjectIdentifiers {
    /**
     * PKCS#1: 1.2.840.113549.1.1
     */
    ASN1ObjectIdentifier pkcs_1 = new ASN1ObjectIdentifier("1.2.840.113549.1.1");
    /**
     * PKCS#1: 1.2.840.113549.1.1.1
     */
    ASN1ObjectIdentifier rsaEncryption = pkcs_1.branch("1");
    /**
     * PKCS#1: 1.2.840.113549.1.1.13
     */
    ASN1ObjectIdentifier sha512WithRSAEncryption = pkcs_1.branch("13");
    /**
     * PKCS#7: 1.2.840.113549.1.7.1
     */
    ASN1ObjectIdentifier data = new ASN1ObjectIdentifier("1.2.840.113549.1.7.1").intern();
    /**
     * PKCS#7: 1.2.840.113549.1.7.2
     */
    ASN1ObjectIdentifier signedData = new ASN1ObjectIdentifier("1.2.840.113549.1.7.2").intern();


    //
    // pkcs-9 OBJECT IDENTIFIER ::= {
    //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 9 }
    //
    /**
     * PKCS#9: 1.2.840.113549.1.9
     */
    ASN1ObjectIdentifier pkcs_9 = new ASN1ObjectIdentifier("1.2.840.113549.1.9");

    /**
     * PKCS#9: 1.2.840.113549.1.9.1
     */
    ASN1ObjectIdentifier pkcs_9_at_emailAddress = pkcs_9.branch("1").intern();
    /**
     * PKCS#9: 1.2.840.113549.1.9.2
     */
    ASN1ObjectIdentifier pkcs_9_at_unstructuredName = pkcs_9.branch("2").intern();
    /**
     * PKCS#9: 1.2.840.113549.1.9.3
     */
    ASN1ObjectIdentifier pkcs_9_at_contentType = pkcs_9.branch("3").intern();
    /**
     * PKCS#9: 1.2.840.113549.1.9.4
     */
    ASN1ObjectIdentifier pkcs_9_at_messageDigest = pkcs_9.branch("4").intern();
    /**
     * PKCS#9: 1.2.840.113549.1.9.5
     */
    ASN1ObjectIdentifier pkcs_9_at_signingTime = pkcs_9.branch("5").intern();
    /**
     * PKCS#9: 1.2.840.113549.1.9.6
     */
    ASN1ObjectIdentifier pkcs_9_at_counterSignature = pkcs_9.branch("6").intern();
    /**
     * PKCS#9: 1.2.840.113549.1.9.8
     */
    ASN1ObjectIdentifier pkcs_9_at_unstructuredAddress = pkcs_9.branch("8").intern();
    /**
     * RFC 6211 -  id-aa-cmsAlgorithmProtect OBJECT IDENTIFIER ::= {
     * iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
     * pkcs9(9) 52 }
     */
    ASN1ObjectIdentifier id_aa_cmsAlgorithmProtect = pkcs_9.branch("52").intern();
}