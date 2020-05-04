package org.bouncycastle.math.raw;

public abstract class Nat {
    private static final long M = 0xFFFFFFFFL;

    public static int cadd(int len, int mask, int[] x, int[] y, int[] z) {
        long MASK = -(mask & 1) & M;
        long c = 0;
        for (int i = 0; i < len; ++i) {
            c += (x[i] & M) + (y[i] & MASK);
            z[i] = (int) c;
            c >>>= 32;
        }
        return (int) c;
    }

    public static int shiftDownBit(int len, int[] z, int c) {
        int i = len;
        while (--i >= 0) {
            int next = z[i];
            z[i] = (next >>> 1) | (c << 31);
            c = next;
        }
        return c << 31;
    }

    /**
     * @deprecated Use {@link #squareWordAddTo(int[], int, int[])} instead.
     */
    public static int squareWordAdd(int[] x, int xPos, int[] z) {
        long c = 0, xVal = x[xPos] & M;
        int i = 0;
        do {
            c += xVal * (x[i] & M) + (z[xPos + i] & M);
            z[xPos + i] = (int) c;
            c >>>= 32;
        }
        while (++i < xPos);
        return (int) c;
    }

    /**
     * @deprecated Use {@link #squareWordAddTo(int[], int, int, int[], int)} instead.
     */
    public static int squareWordAdd(int[] x, int xOff, int xPos, int[] z, int zOff) {
        long c = 0, xVal = x[xOff + xPos] & M;
        int i = 0;
        do {
            c += xVal * (x[xOff + i] & M) + (z[xPos + zOff] & M);
            z[xPos + zOff] = (int) c;
            c >>>= 32;
            ++zOff;
        }
        while (++i < xPos);
        return (int) c;
    }
}