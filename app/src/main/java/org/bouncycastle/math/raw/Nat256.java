package org.bouncycastle.math.raw;

public abstract class Nat256 {
    private static final long M = 0xFFFFFFFFL;

    public static boolean gte(int[] x, int[] y) {
        for (int i = 7; i >= 0; --i) {
            int x_i = x[i] ^ Integer.MIN_VALUE;
            int y_i = y[i] ^ Integer.MIN_VALUE;
            if (x_i < y_i)
                return false;
            if (x_i > y_i)
                return true;
        }
        return true;
    }

    public static int mulAddTo(int[] x, int[] y, int[] zz) {
        long y_0 = y[0] & M;
        long y_1 = y[1] & M;
        long y_2 = y[2] & M;
        long y_3 = y[3] & M;
        long y_4 = y[4] & M;
        long y_5 = y[5] & M;
        long y_6 = y[6] & M;
        long y_7 = y[7] & M;

        long zc = 0;
        for (int i = 0; i < 8; ++i) {
            long c = 0, x_i = x[i] & M;
            c += x_i * y_0 + (zz[i + 0] & M);
            zz[i + 0] = (int) c;
            c >>>= 32;
            c += x_i * y_1 + (zz[i + 1] & M);
            zz[i + 1] = (int) c;
            c >>>= 32;
            c += x_i * y_2 + (zz[i + 2] & M);
            zz[i + 2] = (int) c;
            c >>>= 32;
            c += x_i * y_3 + (zz[i + 3] & M);
            zz[i + 3] = (int) c;
            c >>>= 32;
            c += x_i * y_4 + (zz[i + 4] & M);
            zz[i + 4] = (int) c;
            c >>>= 32;
            c += x_i * y_5 + (zz[i + 5] & M);
            zz[i + 5] = (int) c;
            c >>>= 32;
            c += x_i * y_6 + (zz[i + 6] & M);
            zz[i + 6] = (int) c;
            c >>>= 32;
            c += x_i * y_7 + (zz[i + 7] & M);
            zz[i + 7] = (int) c;
            c >>>= 32;

            zc += c + (zz[i + 8] & M);
            zz[i + 8] = (int) zc;
            zc >>>= 32;
        }
        return (int) zc;
    }

}