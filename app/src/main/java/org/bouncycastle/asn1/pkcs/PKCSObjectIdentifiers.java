package org.bouncycastle.asn1.pkcs;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

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
     * PKCS#1: 1.2.840.113549.1.1.8
     */
    ASN1ObjectIdentifier id_mgf1 = pkcs_1.branch("8");
    /**
     * PKCS#1: 1.2.840.113549.1.1.9
     */
    ASN1ObjectIdentifier id_pSpecified = pkcs_1.branch("9");
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
     * PKCS#9: 1.2.840.113549.1.9.7
     */
    ASN1ObjectIdentifier pkcs_9_at_challengePassword = pkcs_9.branch("7").intern();
    /**
     * PKCS#9: 1.2.840.113549.1.9.8
     */
    ASN1ObjectIdentifier pkcs_9_at_unstructuredAddress = pkcs_9.branch("8").intern();
    /**
     * PKCS#9: 1.2.840.113549.1.9.22.1
     *
     * @deprecated use x509Certificate instead
     */
    ASN1ObjectIdentifier x509certType = pkcs_9.branch("22.1");


    /**
     * RFC 6211 -  id-aa-cmsAlgorithmProtect OBJECT IDENTIFIER ::= {
     * iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
     * pkcs9(9) 52 }
     */
    ASN1ObjectIdentifier id_aa_cmsAlgorithmProtect = pkcs_9.branch("52").intern();


    //
    // id-aa OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840)
    // rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) attributes(2)}
    //
    /**
     * PKCS#9: 1.2.840.113549.1.9.16.2 - smime attributes
     */
    ASN1ObjectIdentifier id_aa = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2");


    /**
     * PKCS#9: 1.2.840.113549.1.9.16.2.4 - See <a href="http://tools.ietf.org/html/rfc2634">RFC 2634</a>
     */
    ASN1ObjectIdentifier id_aa_contentHint = id_aa.branch("4"); // See RFC 2634


    /**
     * PKCS#9: 1.2.840.113549.1.9.16.2.15 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a>
     */
    ASN1ObjectIdentifier id_aa_ets_sigPolicyId = id_aa.branch("15");
    /**
     * PKCS#9: 1.2.840.113549.1.9.16.2.16 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a>
     */
    ASN1ObjectIdentifier id_aa_ets_commitmentType = id_aa.branch("16");
    /**
     * PKCS#9: 1.2.840.113549.1.9.16.2.17 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a>
     */
    ASN1ObjectIdentifier id_aa_ets_signerLocation = id_aa.branch("17");
    /**
     * PKCS#9: 1.2.840.113549.1.9.16.6.2.19 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a>
     */
    ASN1ObjectIdentifier id_aa_ets_otherSigCert = id_aa.branch("19");
    /**
     * @deprecated use id_aa_ets_sigPolicyId instead
     */
    ASN1ObjectIdentifier id_aa_sigPolicyId = id_aa_ets_sigPolicyId;
    /**
     * @deprecated use id_aa_ets_commitmentType instead
     */
    ASN1ObjectIdentifier id_aa_commitmentType = id_aa_ets_commitmentType;
    /**
     * @deprecated use id_aa_ets_signerLocation instead
     */
    ASN1ObjectIdentifier id_aa_signerLocation = id_aa_ets_signerLocation;
    /**
     * @deprecated use id_aa_ets_otherSigCert instead
     */
    ASN1ObjectIdentifier id_aa_otherSigCert = id_aa_ets_otherSigCert;

    /**
     * id-spq OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840)
     * rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-spq(5)}; <p>
     * 1.2.840.113549.1.9.16.5
     */
    String id_spq = "1.2.840.113549.1.9.16.5";

    //
    // pkcs-12 OBJECT IDENTIFIER ::= {
    //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 12 }
    //
    /**
     * PKCS#12: 1.2.840.113549.1.12
     */
    ASN1ObjectIdentifier pkcs_12 = new ASN1ObjectIdentifier("1.2.840.113549.1.12");

    /**
     * PKCS#12: 1.2.840.113549.1.12.1
     */
    ASN1ObjectIdentifier pkcs_12PbeIds = pkcs_12.branch("1");

    /**
     * PKCS#12: 1.2.840.113549.1.12.1.6
     *
     * @deprecated use pbeWithSHAAnd40BitRC2_CBC
     */
    ASN1ObjectIdentifier pbewithSHAAnd40BitRC2_CBC = pkcs_12PbeIds.branch("6");
}