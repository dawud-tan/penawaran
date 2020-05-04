package org.bouncycastle.jce.provider;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jcajce.provider.symmetric.util.ClassUtil;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;


/**
 * To add the provider at runtime use:
 * <pre>
 * import java.security.Security;
 * import org.bouncycastle.jce.provider.BouncyCastleProvider;
 *
 * Security.addProvider(new BouncyCastleProvider());
 * </pre>
 * The provider can also be configured as part of your environment via
 * static registration by adding an entry to the java.security properties
 * file (found in $JAVA_HOME/jre/lib/security/java.security, where
 * $JAVA_HOME is the location of your JDK/JRE distribution). You'll find
 * detailed instructions in the file but basically it comes down to adding
 * a line:
 * <pre>
 * <code>
 *    security.provider.&lt;n&gt;=org.bouncycastle.jce.provider.BouncyCastleProvider
 * </code>
 * </pre>
 * Where &lt;n&gt; is the preference you want the provider at (1 being the
 * most preferred).
 * <p>Note: JCE algorithm names should be upper-case only so the case insensitive
 * test for getInstance works.
 */
public final class BouncyCastleProvider extends Provider
        implements ConfigurableProvider {
    private static String info = "BouncyCastle Security Provider v1.65";

    public static final String PROVIDER_NAME = "BC25519";

    public static final ProviderConfiguration CONFIGURATION = new BouncyCastleProviderConfiguration();

    private static final Map keyInfoConverters = new HashMap();

    /*
     * Configurable asymmetric ciphers
     */
    private static final String ASYMMETRIC_PACKAGE = "org.bouncycastle.jcajce.provider.asymmetric.";

    // this one is required for GNU class path - it needs to be loaded first as the
    // later ones configure it.
    private static final String[] ASYMMETRIC_GENERIC =
            {
                    "X509"
            };

    private static final String[] ASYMMETRIC_CIPHERS =
            {
                    "EdEC"
            };

    /*
     * Configurable digests
     */
    private static final String DIGEST_PACKAGE = "org.bouncycastle.jcajce.provider.digest.";
    private static final String[] DIGESTS =
            {
                    "SHA512"
            };

    /**
     * Construct a new provider.  This should only be required when
     * using runtime registration of the provider using the
     * <code>Security.addProvider()</code> mechanism.
     */
    public BouncyCastleProvider() {
        super(PROVIDER_NAME, 1.65, info);

        AccessController.doPrivileged((PrivilegedAction) () -> {
            setup();
            return null;
        });
    }

    private void setup() {
        loadAlgorithms(DIGEST_PACKAGE, DIGESTS);

        loadAlgorithms(ASYMMETRIC_PACKAGE, ASYMMETRIC_GENERIC);

        loadAlgorithms(ASYMMETRIC_PACKAGE, ASYMMETRIC_CIPHERS);
    }

    private void loadAlgorithms(String packageName, String[] names) {
        for (int i = 0; i != names.length; i++) {
            Class clazz = ClassUtil.loadClass(BouncyCastleProvider.class, packageName + names[i] + "$Mappings");

            if (clazz != null) {
                try {
                    ((AlgorithmProvider) clazz.newInstance()).configure(this);
                } catch (Exception e) {   // this should never ever happen!!
                    throw new InternalError("cannot create instance of "
                            + packageName + names[i] + "$Mappings : " + e);
                }
            }
        }
    }


    public void addAlgorithm(String key, String value) {
        if (containsKey(key)) {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        put(key, value);
    }

    public void addAlgorithm(String type, ASN1ObjectIdentifier oid, String className) {
        addAlgorithm(type + "." + oid, className);
        addAlgorithm(type + ".OID." + oid, className);
    }

    public void addKeyInfoConverter(ASN1ObjectIdentifier oid, AsymmetricKeyInfoConverter keyInfoConverter) {
        synchronized (keyInfoConverters) {
            keyInfoConverters.put(oid, keyInfoConverter);
        }
    }


    private static AsymmetricKeyInfoConverter getAsymmetricKeyInfoConverter(ASN1ObjectIdentifier algorithm) {
        synchronized (keyInfoConverters) {
            return (AsymmetricKeyInfoConverter) keyInfoConverters.get(algorithm);
        }
    }

    public static PublicKey getPublicKey(SubjectPublicKeyInfo publicKeyInfo)
            throws IOException {
        AsymmetricKeyInfoConverter converter = getAsymmetricKeyInfoConverter(publicKeyInfo.getAlgorithm().getAlgorithm());

        if (converter == null) {
            return null;
        }

        return converter.generatePublic(publicKeyInfo);
    }

    public static PrivateKey getPrivateKey(PrivateKeyInfo privateKeyInfo)
            throws IOException {
        AsymmetricKeyInfoConverter converter = getAsymmetricKeyInfoConverter(privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm());

        if (converter == null) {
            return null;
        }

        return converter.generatePrivate(privateKeyInfo);
    }
}