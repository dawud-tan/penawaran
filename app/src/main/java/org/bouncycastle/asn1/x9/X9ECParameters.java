package org.bouncycastle.asn1.x9;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.field.PolynomialExtensionField;
import org.bouncycastle.util.Arrays;

import java.math.BigInteger;

/**
 * ASN.1 def for Elliptic-Curve ECParameters structure. See
 * X9.62, for further details.
 */
public class X9ECParameters
        extends ASN1Object
        implements X9ObjectIdentifiers {
    private static final BigInteger ONE = BigInteger.valueOf(1);

    private X9FieldID fieldID;
    private ECCurve curve;
    private X9ECPoint g;
    private BigInteger n;
    private BigInteger h;
    private byte[] seed;


    public X9ECParameters(
            ECCurve curve,
            X9ECPoint g,
            BigInteger n,
            BigInteger h) {
        this(curve, g, n, h, null);
    }

    public X9ECParameters(
            ECCurve curve,
            X9ECPoint g,
            BigInteger n,
            BigInteger h,
            byte[] seed) {
        this.curve = curve;
        this.g = g;
        this.n = n;
        this.h = h;
        this.seed = Arrays.clone(seed);

        if (ECAlgorithms.isFpCurve(curve)) {
            this.fieldID = new X9FieldID(curve.getField().getCharacteristic());
        } else if (ECAlgorithms.isF2mCurve(curve)) {
            PolynomialExtensionField field = (PolynomialExtensionField) curve.getField();
            int[] exponents = field.getMinimalPolynomial().getExponentsPresent();
            if (exponents.length == 3) {
                this.fieldID = new X9FieldID(exponents[2], exponents[1]);
            } else if (exponents.length == 5) {
                this.fieldID = new X9FieldID(exponents[4], exponents[1], exponents[2], exponents[3]);
            } else {
                throw new IllegalArgumentException("Only trinomial and pentomial curves are supported");
            }
        } else {
            throw new IllegalArgumentException("'curve' is of an unsupported type");
        }
    }

    public ECCurve getCurve() {
        return curve;
    }

    public ECPoint getG() {
        return g.getPoint();
    }

    public BigInteger getN() {
        return n;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  ECParameters ::= SEQUENCE {
     *      version         INTEGER { ecpVer1(1) } (ecpVer1),
     *      fieldID         FieldID {{FieldTypes}},
     *      curve           X9Curve,
     *      base            X9ECPoint,
     *      order           INTEGER,
     *      cofactor        INTEGER OPTIONAL
     *  }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(6);

        v.add(new ASN1Integer(ONE));
        v.add(fieldID);
        v.add(new X9Curve(curve, seed));
        v.add(g);
        v.add(new ASN1Integer(n));

        if (h != null) {
            v.add(new ASN1Integer(h));
        }

        return new DERSequence(v);
    }
}
