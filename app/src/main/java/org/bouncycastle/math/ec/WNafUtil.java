package org.bouncycastle.math.ec;

import java.math.BigInteger;

public abstract class WNafUtil {
    public static final String PRECOMP_NAME = "bc_wnaf";

    private static final int[] DEFAULT_WINDOW_SIZE_CUTOFFS = new int[]{13, 41, 121, 337, 897, 2305};
    private static final int MAX_WIDTH = 16;

    private static final int[] EMPTY_INTS = new int[0];
    private static final ECPoint[] EMPTY_POINTS = new ECPoint[0];

    public static void configureBasepoint(ECPoint p) {
        final ECCurve c = p.getCurve();
        if (null == c) {
            return;
        }

        BigInteger n = c.getOrder();
        int bits = (null == n) ? c.getFieldSize() + 1 : n.bitLength();
        final int confWidth = Math.min(MAX_WIDTH, getWindowSize(bits) + 3);

        c.precompute(p, PRECOMP_NAME, new PreCompCallback() {
            public PreCompInfo precompute(PreCompInfo existing) {
                WNafPreCompInfo existingWNaf = (existing instanceof WNafPreCompInfo) ? (WNafPreCompInfo) existing : null;

                if (null != existingWNaf && existingWNaf.getConfWidth() == confWidth) {
                    existingWNaf.setPromotionCountdown(0);
                    return existingWNaf;
                }

                WNafPreCompInfo result = new WNafPreCompInfo();

                result.setPromotionCountdown(0);
                result.setConfWidth(confWidth);

                if (null != existingWNaf) {
                    result.setPreComp(existingWNaf.getPreComp());
                    result.setPreCompNeg(existingWNaf.getPreCompNeg());
                    result.setTwice(existingWNaf.getTwice());
                    result.setWidth(existingWNaf.getWidth());
                }

                return result;
            }
        });
    }

    public static int[] generateCompactNaf(BigInteger k) {
        if ((k.bitLength() >>> 16) != 0) {
            throw new IllegalArgumentException("'k' must have bitlength < 2^16");
        }
        if (k.signum() == 0) {
            return EMPTY_INTS;
        }

        BigInteger _3k = k.shiftLeft(1).add(k);

        int bits = _3k.bitLength();
        int[] naf = new int[bits >> 1];

        BigInteger diff = _3k.xor(k);

        int highBit = bits - 1, length = 0, zeroes = 0;
        for (int i = 1; i < highBit; ++i) {
            if (!diff.testBit(i)) {
                ++zeroes;
                continue;
            }

            int digit = k.testBit(i) ? -1 : 1;
            naf[length++] = (digit << 16) | zeroes;
            zeroes = 1;
            ++i;
        }

        naf[length++] = (1 << 16) | zeroes;

        if (naf.length > length) {
            naf = trim(naf, length);
        }

        return naf;
    }

    public static int[] generateCompactWindowNaf(int width, BigInteger k) {
        if (width == 2) {
            return generateCompactNaf(k);
        }

        if (width < 2 || width > 16) {
            throw new IllegalArgumentException("'width' must be in the range [2, 16]");
        }
        if ((k.bitLength() >>> 16) != 0) {
            throw new IllegalArgumentException("'k' must have bitlength < 2^16");
        }
        if (k.signum() == 0) {
            return EMPTY_INTS;
        }

        int[] wnaf = new int[k.bitLength() / width + 1];

        // 2^width and a mask and sign bit set accordingly
        int pow2 = 1 << width;
        int mask = pow2 - 1;
        int sign = pow2 >>> 1;

        boolean carry = false;
        int length = 0, pos = 0;

        while (pos <= k.bitLength()) {
            if (k.testBit(pos) == carry) {
                ++pos;
                continue;
            }

            k = k.shiftRight(pos);

            int digit = k.intValue() & mask;
            if (carry) {
                ++digit;
            }

            carry = (digit & sign) != 0;
            if (carry) {
                digit -= pow2;
            }

            int zeroes = length > 0 ? pos - 1 : pos;
            wnaf[length++] = (digit << 16) | zeroes;
            pos = width;
        }

        // Reduce the WNAF array to its actual length
        if (wnaf.length > length) {
            wnaf = trim(wnaf, length);
        }

        return wnaf;
    }

    /**
     * Determine window width to use for a scalar multiplication of the given size.
     *
     * @param bits the bit-length of the scalar to multiply by
     * @return the window size to use
     */
    public static int getWindowSize(int bits) {
        return getWindowSize(bits, DEFAULT_WINDOW_SIZE_CUTOFFS, MAX_WIDTH);
    }


    /**
     * Determine window width to use for a scalar multiplication of the given size.
     *
     * @param bits              the bit-length of the scalar to multiply by
     * @param windowSizeCutoffs a monotonically increasing list of bit sizes at which to increment the window width
     * @param maxWidth          the maximum window width to return
     * @return the window size to use
     */
    public static int getWindowSize(int bits, int[] windowSizeCutoffs, int maxWidth) {
        int w = 0;
        for (; w < windowSizeCutoffs.length; ++w) {
            if (bits < windowSizeCutoffs[w]) {
                break;
            }
        }

        return Math.max(2, Math.min(maxWidth, w + 2));
    }

    /**
     * @deprecated
     */
    public static ECPoint mapPointWithPrecomp(ECPoint p, final int minWidth, final boolean includeNegated,
                                              final ECPointMap pointMap) {
        final ECCurve c = p.getCurve();
        final WNafPreCompInfo infoP = precompute(p, minWidth, includeNegated);

        ECPoint q = pointMap.map(p);
        c.precompute(q, PRECOMP_NAME, existing -> {
            WNafPreCompInfo result = new WNafPreCompInfo();

            result.setConfWidth(infoP.getConfWidth());

            ECPoint twiceP = infoP.getTwice();
            if (null != twiceP) {
                ECPoint twiceQ = pointMap.map(twiceP);
                result.setTwice(twiceQ);
            }

            ECPoint[] preCompP = infoP.getPreComp();
            ECPoint[] preCompQ = new ECPoint[preCompP.length];
            for (int i = 0; i < preCompP.length; ++i) {
                preCompQ[i] = pointMap.map(preCompP[i]);
            }
            result.setPreComp(preCompQ);
            result.setWidth(infoP.getWidth());

            if (includeNegated) {
                ECPoint[] preCompNegQ = new ECPoint[preCompQ.length];
                for (int i = 0; i < preCompNegQ.length; ++i) {
                    preCompNegQ[i] = preCompQ[i].negate();
                }
                result.setPreCompNeg(preCompNegQ);
            }

            return result;
        });

        return q;
    }

    public static WNafPreCompInfo precompute(final ECPoint p, final int minWidth, final boolean includeNegated) {
        final ECCurve c = p.getCurve();

        return (WNafPreCompInfo) c.precompute(p, PRECOMP_NAME, new PreCompCallback() {
            public PreCompInfo precompute(PreCompInfo existing) {
                WNafPreCompInfo existingWNaf = (existing instanceof WNafPreCompInfo) ? (WNafPreCompInfo) existing : null;

                int width = Math.max(2, Math.min(MAX_WIDTH, minWidth));
                int reqPreCompLen = 1 << (width - 2);

                if (checkExisting(existingWNaf, width, reqPreCompLen, includeNegated)) {
                    existingWNaf.decrementPromotionCountdown();
                    return existingWNaf;
                }

                WNafPreCompInfo result = new WNafPreCompInfo();

                ECPoint[] preComp = null, preCompNeg = null;
                ECPoint twiceP = null;

                if (null != existingWNaf) {
                    int promotionCountdown = existingWNaf.decrementPromotionCountdown();
                    result.setPromotionCountdown(promotionCountdown);

                    int confWidth = existingWNaf.getConfWidth();
                    result.setConfWidth(confWidth);

                    preComp = existingWNaf.getPreComp();
                    preCompNeg = existingWNaf.getPreCompNeg();
                    twiceP = existingWNaf.getTwice();
                }

                width = Math.min(MAX_WIDTH, Math.max(result.getConfWidth(), width));
                reqPreCompLen = 1 << (width - 2);

                int iniPreCompLen = 0;
                if (null == preComp) {
                    preComp = EMPTY_POINTS;
                } else {
                    iniPreCompLen = preComp.length;
                }

                if (iniPreCompLen < reqPreCompLen) {
                    preComp = resizeTable(preComp, reqPreCompLen);

                    if (reqPreCompLen == 1) {
                        preComp[0] = p.normalize();
                    } else {
                        int curPreCompLen = iniPreCompLen;
                        if (curPreCompLen == 0) {
                            preComp[0] = p;
                            curPreCompLen = 1;
                        }

                        ECFieldElement iso = null;

                        if (reqPreCompLen == 2) {
                            preComp[1] = p.threeTimes();
                        } else {
                            ECPoint isoTwiceP = twiceP, last = preComp[curPreCompLen - 1];
                            if (null == isoTwiceP) {
                                isoTwiceP = preComp[0].twice();
                                twiceP = isoTwiceP;

                                /*
                                 * For Fp curves with Jacobian projective coordinates, use a (quasi-)isomorphism
                                 * where 'twiceP' is "affine", so that the subsequent additions are cheaper. This
                                 * also requires scaling the initial point's X, Y coordinates, and reversing the
                                 * isomorphism as part of the subsequent normalization.
                                 *
                                 *  NOTE: The correctness of this optimization depends on:
                                 *      1) additions do not use the curve's A, B coefficients.
                                 *      2) no special cases (i.e. Q +/- Q) when calculating 1P, 3P, 5P, ...
                                 */
                                if (!twiceP.isInfinity() && ECAlgorithms.isFpCurve(c) && c.getFieldSize() >= 64) {
                                    switch (c.getCoordinateSystem()) {
                                        case ECCurve.COORD_JACOBIAN:
                                        case ECCurve.COORD_JACOBIAN_CHUDNOVSKY:
                                        case ECCurve.COORD_JACOBIAN_MODIFIED: {
                                            iso = twiceP.getZCoord(0);
                                            isoTwiceP = c.createPoint(twiceP.getXCoord().toBigInteger(), twiceP.getYCoord()
                                                    .toBigInteger());

                                            ECFieldElement iso2 = iso.square(), iso3 = iso2.multiply(iso);
                                            last = last.scaleX(iso2).scaleY(iso3);

                                            if (iniPreCompLen == 0) {
                                                preComp[0] = last;
                                            }
                                            break;
                                        }
                                    }
                                }
                            }

                            while (curPreCompLen < reqPreCompLen) {
                                /*
                                 * Compute the new ECPoints for the precomputation array. The values 1, 3,
                                 * 5, ..., 2^(width-1)-1 times p are computed
                                 */
                                preComp[curPreCompLen++] = last = last.add(isoTwiceP);
                            }
                        }

                        /*
                         * Having oft-used operands in affine form makes operations faster.
                         */
                        c.normalizeAll(preComp, iniPreCompLen, reqPreCompLen - iniPreCompLen, iso);
                    }
                }

                if (includeNegated) {
                    int pos;
                    if (null == preCompNeg) {
                        pos = 0;
                        preCompNeg = new ECPoint[reqPreCompLen];
                    } else {
                        pos = preCompNeg.length;
                        if (pos < reqPreCompLen) {
                            preCompNeg = resizeTable(preCompNeg, reqPreCompLen);
                        }
                    }

                    while (pos < reqPreCompLen) {
                        preCompNeg[pos] = preComp[pos].negate();
                        ++pos;
                    }
                }

                result.setPreComp(preComp);
                result.setPreCompNeg(preCompNeg);
                result.setTwice(twiceP);
                result.setWidth(width);
                return result;
            }

            private boolean checkExisting(WNafPreCompInfo existingWNaf, int width, int reqPreCompLen, boolean includeNegated) {
                return null != existingWNaf
                        && existingWNaf.getWidth() >= Math.max(existingWNaf.getConfWidth(), width)
                        && checkTable(existingWNaf.getPreComp(), reqPreCompLen)
                        && (!includeNegated || checkTable(existingWNaf.getPreCompNeg(), reqPreCompLen));
            }

            private boolean checkTable(ECPoint[] table, int reqLen) {
                return null != table && table.length >= reqLen;
            }
        });
    }

    private static int[] trim(int[] a, int length) {
        int[] result = new int[length];
        System.arraycopy(a, 0, result, 0, result.length);
        return result;
    }

    private static ECPoint[] resizeTable(ECPoint[] a, int length) {
        ECPoint[] result = new ECPoint[length];
        System.arraycopy(a, 0, result, 0, a.length);
        return result;
    }
}
