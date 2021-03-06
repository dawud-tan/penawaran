package org.spongycastle.cms;

import org.spongycastle.asn1.cms.AttributeTable;

import java.util.Map;

/**
 * Note: The SIGNATURE parameter is only available when generating unsigned attributes.
 */
public interface CMSAttributeTableGenerator {
    String CONTENT_TYPE = "contentType";
    String DIGEST = "digest";
    String SIGNATURE = "encryptedDigest";
    String DIGEST_ALGORITHM_IDENTIFIER = "digestAlgID";
    String SIGNATURE_ALGORITHM_IDENTIFIER = "signatureAlgID";

    AttributeTable getAttributes(Map parameters)
            throws CMSAttributeTableGenerationException;
}
