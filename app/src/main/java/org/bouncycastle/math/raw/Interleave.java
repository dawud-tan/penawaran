package org.bouncycastle.math.raw;

public class Interleave {

    public static int shuffle2(int x) {
        // "shuffle" (twice) low half to even bits and high half to odd bits
        int t;
        t = (x ^ (x >>> 7)) & 0x00AA00AA;
        x ^= (t ^ (t << 7));
        t = (x ^ (x >>> 14)) & 0x0000CCCC;
        x ^= (t ^ (t << 14));
        t = (x ^ (x >>> 4)) & 0x00F000F0;
        x ^= (t ^ (t << 4));
        t = (x ^ (x >>> 8)) & 0x0000FF00;
        x ^= (t ^ (t << 8));
        return x;
    }
}