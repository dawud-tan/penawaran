package id.menawar.menerima.utility;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Extract PrivateKey, PublicKey, and X509Certificate from a DER encoded byte array or file.  Usually
 * generated from openssl
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public final class DerUtils {
    static {
        BouncyIntegration.init();
    }

    private DerUtils() {
    }

    public static X509Certificate decodeCertificate(InputStream is) throws IOException, CertificateException, NoSuchProviderException {
        final CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC25519");
        final X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        is.close();
        return cert;
    }

    public static PrivateKey decodePrivateKey(byte[] der, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        final PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        KeyFactory kf = KeyFactory.getInstance(algorithm, "BC25519");
        return kf.generatePrivate(spec);
    }
}