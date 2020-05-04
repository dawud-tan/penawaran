package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BEROctetStringGenerator;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.io.TeeOutputStream;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

class CMSUtils {

    static boolean isEquivalent(AlgorithmIdentifier algId1, AlgorithmIdentifier algId2) {
        if (algId1 == null || algId2 == null) {
            return false;
        }

        if (!algId1.getAlgorithm().equals(algId2.getAlgorithm())) {
            return false;
        }

        ASN1Encodable params1 = algId1.getParameters();
        ASN1Encodable params2 = algId2.getParameters();
        if (params1 != null) {
            return params1.equals(params2) || (params1.equals(DERNull.INSTANCE) && params2 == null);
        }

        return params2 == null || params2.equals(DERNull.INSTANCE);
    }

    static ContentInfo readContentInfo(
            InputStream input)
            throws CMSException {
        // enforce some limit checking
        return readContentInfo(new ASN1InputStream(input));
    }

    static ASN1Set createBerSetFromList(List derObjects) {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (Iterator it = derObjects.iterator(); it.hasNext(); ) {
            v.add((ASN1Encodable) it.next());
        }

        return new BERSet(v);
    }


    static OutputStream createBEROctetOutputStream(OutputStream s,
                                                   int tagNo, boolean isExplicit, int bufferSize)
            throws IOException {
        BEROctetStringGenerator octGen = new BEROctetStringGenerator(s, tagNo, isExplicit);

        if (bufferSize != 0) {
            return octGen.getOctetOutputStream(new byte[bufferSize]);
        }

        return octGen.getOctetOutputStream();
    }

    private static ContentInfo readContentInfo(
            ASN1InputStream in)
            throws CMSException {
        try {
            ContentInfo info = ContentInfo.getInstance(in.readObject());
            if (info == null) {
                throw new CMSException("No content found.");
            }

            return info;
        } catch (IOException e) {
            throw new CMSException("IOException reading content.", e);
        } catch (ClassCastException e) {
            throw new CMSException("Malformed content.", e);
        } catch (IllegalArgumentException e) {
            throw new CMSException("Malformed content.", e);
        }
    }

    static OutputStream attachSignersToOutputStream(Collection signers, OutputStream s) {
        OutputStream result = s;
        Iterator it = signers.iterator();
        while (it.hasNext()) {
            SignerInfoGenerator signerGen = (SignerInfoGenerator) it.next();
            result = getSafeTeeOutputStream(result, signerGen.getCalculatingOutputStream());
        }
        return result;
    }

    static OutputStream getSafeOutputStream(OutputStream s) {
        return s == null ? new NullOutputStream() : s;
    }

    static OutputStream getSafeTeeOutputStream(OutputStream s1,
                                               OutputStream s2) {
        return s1 == null ? getSafeOutputStream(s2)
                : s2 == null ? getSafeOutputStream(s1) : new TeeOutputStream(
                s1, s2);
    }
}