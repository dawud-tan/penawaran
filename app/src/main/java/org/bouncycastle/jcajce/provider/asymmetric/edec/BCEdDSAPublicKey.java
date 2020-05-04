package org.bouncycastle.jcajce.provider.asymmetric.edec;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.spec.InvalidKeySpecException;

public class BCEdDSAPublicKey
        implements EdDSAPublicKey {
    static final long serialVersionUID = 1L;

    private transient AsymmetricKeyParameter eddsaPublicKey;

    BCEdDSAPublicKey(AsymmetricKeyParameter pubKey) {
        this.eddsaPublicKey = pubKey;
    }

    BCEdDSAPublicKey(SubjectPublicKeyInfo keyInfo) {
        populateFromPubKeyInfo(keyInfo);
    }

    BCEdDSAPublicKey(byte[] prefix, byte[] rawData)
            throws InvalidKeySpecException {
        int prefixLength = prefix.length;

        if (Utils.isValidPrefix(prefix, rawData)) {
            if ((rawData.length - prefixLength) == Ed25519PublicKeyParameters.KEY_SIZE) {
                eddsaPublicKey = new Ed25519PublicKeyParameters(rawData, prefixLength);
            } else {
                throw new InvalidKeySpecException("raw key data not recognised");
            }
        } else {
            throw new InvalidKeySpecException("raw key data not recognised");
        }
    }

    private void populateFromPubKeyInfo(SubjectPublicKeyInfo keyInfo) {
        eddsaPublicKey = new Ed25519PublicKeyParameters(keyInfo.getPublicKeyData().getOctets(), 0);
    }

    public String getAlgorithm() {
        return "Ed25519";
    }

    public String getFormat() {
        return "X.509";
    }

    public byte[] getEncoded() {
        byte[] encoding = new byte[KeyFactorySpi.Ed25519Prefix.length + Ed25519PublicKeyParameters.KEY_SIZE];
        System.arraycopy(KeyFactorySpi.Ed25519Prefix, 0, encoding, 0, KeyFactorySpi.Ed25519Prefix.length);
        ((Ed25519PublicKeyParameters) eddsaPublicKey).encode(encoding, KeyFactorySpi.Ed25519Prefix.length);
        return encoding;
    }

    AsymmetricKeyParameter engineGetKeyParameters() {
        return eddsaPublicKey;
    }


    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }

        if (!(o instanceof BCEdDSAPublicKey)) {
            return false;
        }

        BCEdDSAPublicKey other = (BCEdDSAPublicKey) o;

        return Arrays.areEqual(other.getEncoded(), this.getEncoded());
    }

    public int hashCode() {
        return Arrays.hashCode(this.getEncoded());
    }

    private void readObject(
            ObjectInputStream in)
            throws IOException, ClassNotFoundException {
        in.defaultReadObject();

        byte[] enc = (byte[]) in.readObject();

        populateFromPubKeyInfo(SubjectPublicKeyInfo.getInstance(enc));
    }

    private void writeObject(
            ObjectOutputStream out)
            throws IOException {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
