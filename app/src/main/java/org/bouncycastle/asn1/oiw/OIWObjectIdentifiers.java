package org.bouncycastle.asn1.oiw;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * OIW organization's OIDs:
 * <p>
 * id-SHA1 OBJECT IDENTIFIER ::=    
 *   {iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) 26 }
 */
public interface OIWObjectIdentifiers
{
    /** OID: 1.3.14.3.2.2 */
    ASN1ObjectIdentifier    md4WithRSA              = new ASN1ObjectIdentifier("1.3.14.3.2.2");
    /** OID: 1.3.14.3.2.3 */
    ASN1ObjectIdentifier    md5WithRSA              = new ASN1ObjectIdentifier("1.3.14.3.2.3");
    /** OID: 1.3.14.3.2.4 */
    ASN1ObjectIdentifier    md4WithRSAEncryption    = new ASN1ObjectIdentifier("1.3.14.3.2.4");
    
    /** OID: 1.3.14.3.2.6 */
    ASN1ObjectIdentifier    desECB                  = new ASN1ObjectIdentifier("1.3.14.3.2.6");
    /** OID: 1.3.14.3.2.7 */
    ASN1ObjectIdentifier    desCBC                  = new ASN1ObjectIdentifier("1.3.14.3.2.7");
    /** OID: 1.3.14.3.2.8 */
    ASN1ObjectIdentifier    desOFB                  = new ASN1ObjectIdentifier("1.3.14.3.2.8");
    /** OID: 1.3.14.3.2.9 */
    ASN1ObjectIdentifier    desCFB                  = new ASN1ObjectIdentifier("1.3.14.3.2.9");

    /** OID: 1.3.14.3.2.17 */
    ASN1ObjectIdentifier    desEDE                  = new ASN1ObjectIdentifier("1.3.14.3.2.17");
    
    /** OID: 1.3.14.3.2.26 */
    ASN1ObjectIdentifier    idSHA1                  = new ASN1ObjectIdentifier("1.3.14.3.2.26");

    /** OID: 1.3.14.3.2.27 */
    ASN1ObjectIdentifier    dsaWithSHA1             = new ASN1ObjectIdentifier("1.3.14.3.2.27");

    /** OID: 1.3.14.3.2.29 */
    ASN1ObjectIdentifier    sha1WithRSA             = new ASN1ObjectIdentifier("1.3.14.3.2.29");
    
    /**
     * <pre>
     * ElGamal Algorithm OBJECT IDENTIFIER ::=    
     *   {iso(1) identified-organization(3) oiw(14) dirservsig(7) algorithm(2) encryption(1) 1 }
     * </pre>
     * OID: 1.3.14.7.2.1.1
     */
    ASN1ObjectIdentifier    elGamalAlgorithm        = new ASN1ObjectIdentifier("1.3.14.7.2.1.1");

}
