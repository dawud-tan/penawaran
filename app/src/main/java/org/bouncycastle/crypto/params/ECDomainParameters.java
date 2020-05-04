package org.bouncycastle.crypto.params;

import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

import java.math.BigInteger;

public class ECDomainParameters
        implements ECConstants {
    private final ECCurve curve;
    private final byte[] seed;
    private final ECPoint G;
    private final BigInteger n;
    private final BigInteger h;

    private BigInteger hInv = null;


    public ECDomainParameters(
            ECCurve curve,
            ECPoint G,
            BigInteger n,
            BigInteger h) {
        this(curve, G, n, h, null);
    }

    public ECDomainParameters(
            ECCurve curve,
            ECPoint G,
            BigInteger n,
            BigInteger h,
            byte[] seed) {
        if (curve == null) {
            throw new NullPointerException("curve");
        }
        if (n == null) {
            throw new NullPointerException("n");
        }
        // we can't check for h == null here as h is optional in X9.62 as it is not required for ECDSA

        this.curve = curve;
        this.G = validatePublicPoint(curve, G);
        this.n = n;
        this.h = h;
        this.seed = Arrays.clone(seed);
    }

    public boolean equals(
            Object obj) {
        if (this == obj) {
            return true;
        }

        if (!(obj instanceof ECDomainParameters)) {
            return false;
        }

        ECDomainParameters other = (ECDomainParameters) obj;

        return this.curve.equals(other.curve)
                && this.G.equals(other.G)
                && this.n.equals(other.n);
    }

    public int hashCode() {
//        return Arrays.hashCode(new Object[]{ curve, G, n });
        int hc = 4;
        hc *= 257;
        hc ^= curve.hashCode();
        hc *= 257;
        hc ^= G.hashCode();
        hc *= 257;
        hc ^= n.hashCode();
        return hc;
    }

    static ECPoint validatePublicPoint(ECCurve c, ECPoint q) {
        if (null == q) {
            throw new NullPointerException("Point cannot be null");
        }

        q = ECAlgorithms.importPoint(c, q).normalize();

        if (q.isInfinity()) {
            throw new IllegalArgumentException("Point at infinity");
        }

        if (!q.isValid()) {
            throw new IllegalArgumentException("Point not on curve");
        }

        return q;
    }
}
