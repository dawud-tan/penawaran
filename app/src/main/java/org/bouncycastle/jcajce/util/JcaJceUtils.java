package org.bouncycastle.jcajce.util;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

import java.io.IOException;
import java.security.AlgorithmParameters;

/**
 * General JCA/JCE utility methods.
 */
public class JcaJceUtils {
    private JcaJceUtils() {

    }

    /**
     * Extract an ASN.1 encodable from an AlgorithmParameters object.
     *
     * @param params the object to get the encoding used to create the return value.
     * @return an ASN.1 object representing the primitives making up the params parameter.
     * @throws IOException if an encoding cannot be extracted.
     * @deprecated use AlgorithmParametersUtils.extractParameters(AlgorithmParameters params)
     */
    public static ASN1Encodable extractParameters(AlgorithmParameters params)
            throws IOException {
        // we try ASN.1 explicitly first just in case and then role back to the default.
        ASN1Encodable asn1Params;
        try {
            asn1Params = ASN1Primitive.fromByteArray(params.getEncoded("ASN.1"));
        } catch (Exception ex) {
            asn1Params = ASN1Primitive.fromByteArray(params.getEncoded());
        }

        return asn1Params;
    }

    /**
     * Load an AlgorithmParameters object with the passed in ASN.1 encodable - if possible.
     *
     * @param params  the AlgorithmParameters object to be initialised.
     * @param sParams the ASN.1 encodable to initialise params with.
     * @throws IOException if the parameters cannot be initialised.
     * @deprecated use AlgorithmParametersUtils.loadParameters(AlgorithmParameters params, ASN1Encodable sParams)
     */
    public static void loadParameters(AlgorithmParameters params, ASN1Encodable sParams)
            throws IOException {
        // we try ASN.1 explicitly first just in case and then role back to the default.
        try {
            params.init(sParams.toASN1Primitive().getEncoded(), "ASN.1");
        } catch (Exception ex) {
            params.init(sParams.toASN1Primitive().getEncoded());
        }
    }

    /**
     * Attempt to find a standard JCA name for the digest represented by the past in OID.
     *
     * @param digestAlgOID the OID of the digest algorithm of interest.
     * @return a string representing the standard name - the OID as a string if none available.
     * @deprecated use MessageDigestUtils,getDigestName()
     */
    public static String getDigestAlgName(
            ASN1ObjectIdentifier digestAlgOID) {
        if (NISTObjectIdentifiers.id_sha512.equals(digestAlgOID)) {
            return "SHA512";
        } else {
            return digestAlgOID.getId();
        }
    }
}
