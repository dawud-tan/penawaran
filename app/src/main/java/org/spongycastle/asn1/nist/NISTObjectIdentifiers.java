package org.spongycastle.asn1.nist;

import org.spongycastle.asn1.ASN1ObjectIdentifier;

/**
 *
 * NIST:
 *     iso/itu(2) joint-assign(16) us(840) organization(1) gov(101) csor(3)
 */
public interface NISTObjectIdentifiers
{
    //
    // nistalgorithms(4)
    //
    /** 2.16.840.1.101.3.4 -- algorithms */
    ASN1ObjectIdentifier    nistAlgorithm           = new ASN1ObjectIdentifier("2.16.840.1.101.3.4");
    /** 2.16.840.1.101.3.4.2 */
    ASN1ObjectIdentifier    hashAlgs                = nistAlgorithm.branch("2");
    /** 2.16.840.1.101.3.4.2.3 */
    ASN1ObjectIdentifier    id_sha512               = hashAlgs.branch("3");
}