package org.bouncycastle.jcajce.provider.asymmetric.edec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class BCEdDSAPrivateKey
        implements EdDSAPrivateKey {
    static final long serialVersionUID = 1L;

    private transient AsymmetricKeyParameter eddsaPrivateKey;

    private final boolean hasPublicKey;
    private final byte[] attributes;


    BCEdDSAPrivateKey(PrivateKeyInfo keyInfo)
            throws IOException {
        this.hasPublicKey = keyInfo.hasPublicKey();
        this.attributes = (keyInfo.getAttributes() != null) ? keyInfo.getAttributes().getEncoded() : null;

        populateFromPrivateKeyInfo(keyInfo);
    }

    private void populateFromPrivateKeyInfo(PrivateKeyInfo keyInfo)
            throws IOException {
        ASN1Encodable keyOcts = keyInfo.parsePrivateKey();
        eddsaPrivateKey = new Ed25519PrivateKeyParameters(ASN1OctetString.getInstance(keyOcts).getOctets(), 0);
    }

    public String getAlgorithm() {
        return "Ed25519";
    }

    public String getFormat() {
        return "PKCS#8";
    }

    public byte[] getEncoded() {
        try {
            ASN1Set attrSet = ASN1Set.getInstance(attributes);
            PrivateKeyInfo privInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(eddsaPrivateKey, attrSet);

            if (hasPublicKey) {
                return privInfo.getEncoded();
            } else {
                return new PrivateKeyInfo(privInfo.getPrivateKeyAlgorithm(), privInfo.parsePrivateKey(), attrSet).getEncoded();
            }
        } catch (IOException e) {
            return null;
        }
    }

    public EdDSAPublicKey getPublicKey() {
        return new BCEdDSAPublicKey(((Ed25519PrivateKeyParameters) eddsaPrivateKey).generatePublicKey());
    }

    AsymmetricKeyParameter engineGetKeyParameters() {
        return eddsaPrivateKey;
    }


    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }

        if (!(o instanceof BCEdDSAPrivateKey)) {
            return false;
        }

        BCEdDSAPrivateKey other = (BCEdDSAPrivateKey) o;

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

        populateFromPrivateKeyInfo(PrivateKeyInfo.getInstance(enc));
    }

    private void writeObject(
            ObjectOutputStream out)
            throws IOException {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
