package org.bouncycastle.util;

import java.util.NoSuchElementException;

/**
 * General array utilities.
 */
public final class Arrays {
    private Arrays() {
        // static class, hide constructor
    }


    public static boolean areEqual(byte[] a, byte[] b) {
        return java.util.Arrays.equals(a, b);
    }


    public static boolean areEqual(char[] a, char[] b) {
        return java.util.Arrays.equals(a, b);
    }

    public static boolean areEqual(int[] a, int[] b) {
        return java.util.Arrays.equals(a, b);
    }


    /**
     * A constant time equals comparison - does not terminate early if
     * test will fail. For best results always pass the expected value
     * as the first parameter.
     *
     * @param expected first array
     * @param supplied second array
     * @return true if arrays equal, false otherwise.
     */
    public static boolean constantTimeAreEqual(
            byte[] expected,
            byte[] supplied) {
        if (expected == null || supplied == null) {
            return false;
        }

        if (expected == supplied) {
            return true;
        }

        int len = (expected.length < supplied.length) ? expected.length : supplied.length;

        int nonEqual = expected.length ^ supplied.length;

        for (int i = 0; i != len; i++) {
            nonEqual |= (expected[i] ^ supplied[i]);
        }
        for (int i = len; i < supplied.length; i++) {
            nonEqual |= (supplied[i] ^ ~supplied[i]);
        }

        return nonEqual == 0;
    }


    /**
     * @deprecated Use {@link #fill(byte[], int, int, byte)} instead.
     */
    public static void fill(byte[] a, int fromIndex, byte val) {
        fill(a, fromIndex, a.length, val);
    }

    public static void fill(byte[] a, int fromIndex, int toIndex, byte val) {
        java.util.Arrays.fill(a, fromIndex, toIndex, val);
    }

    /**
     * @deprecated Use {@link #fill(int[], int, int, int)} instead.
     */
    public static void fill(int[] a, int fromIndex, int val) {
        java.util.Arrays.fill(a, fromIndex, a.length, val);
    }

    /**
     * @deprecated Use {@link #fill(long[], int, int, long)} instead.
     */
    public static void fill(long[] a, int fromIndex, long val) {
        java.util.Arrays.fill(a, fromIndex, a.length, val);
    }

    /**
     * @deprecated Use {@link #fill(short[], int, int, short)} instead.
     */
    public static void fill(short[] a, int fromIndex, short val) {
        java.util.Arrays.fill(a, fromIndex, a.length, val);
    }

    public static int hashCode(byte[] data) {
        if (data == null) {
            return 0;
        }

        int i = data.length;
        int hc = i + 1;

        while (--i >= 0) {
            hc *= 257;
            hc ^= data[i];
        }

        return hc;
    }

    public static int hashCode(byte[] data, int off, int len) {
        if (data == null) {
            return 0;
        }

        int i = len;
        int hc = i + 1;

        while (--i >= 0) {
            hc *= 257;
            hc ^= data[off + i];
        }

        return hc;
    }

    public static int hashCode(char[] data) {
        if (data == null) {
            return 0;
        }

        int i = data.length;
        int hc = i + 1;

        while (--i >= 0) {
            hc *= 257;
            hc ^= data[i];
        }

        return hc;
    }

    public static int hashCode(int[] data) {
        if (data == null) {
            return 0;
        }

        int i = data.length;
        int hc = i + 1;

        while (--i >= 0) {
            hc *= 257;
            hc ^= data[i];
        }

        return hc;
    }

    public static int hashCode(int[] data, int off, int len) {
        if (data == null) {
            return 0;
        }

        int i = len;
        int hc = i + 1;

        while (--i >= 0) {
            hc *= 257;
            hc ^= data[off + i];
        }

        return hc;
    }

    public static boolean[] clone(boolean[] data) {
        return null == data ? null : data.clone();
    }

    public static byte[] clone(byte[] data) {
        return null == data ? null : data.clone();
    }


    public static int[] clone(int[] data) {
        return null == data ? null : data.clone();
    }

    public static long[] clone(long[] data) {
        return null == data ? null : data.clone();
    }


    /**
     * Make a copy of a range of bytes from the passed in array. The range can extend beyond the end
     * of the input array, in which case the returned array will be padded with zeroes.
     *
     * @param original the array from which the data is to be copied.
     * @param from     the start index at which the copying should take place.
     * @param to       the final index of the range (exclusive).
     * @return a new byte array containing the range given.
     */
    public static byte[] copyOfRange(byte[] original, int from, int to) {
        int newLength = getLength(from, to);
        byte[] copy = new byte[newLength];
        System.arraycopy(original, from, copy, 0, Math.min(original.length - from, newLength));
        return copy;
    }


    private static int getLength(int from, int to) {
        int newLength = to - from;
        if (newLength < 0) {
            StringBuffer sb = new StringBuffer(from);
            sb.append(" > ").append(to);
            throw new IllegalArgumentException(sb.toString());
        }
        return newLength;
    }

    /**
     * Iterator backed by a specific array.
     */
    public static class Iterator<T>
            implements java.util.Iterator<T> {
        private final T[] dataArray;

        private int position = 0;

        /**
         * Base constructor.
         * <p>
         * Note: the array is not cloned, changes to it will affect the values returned by next().
         * </p>
         *
         * @param dataArray array backing the iterator.
         */
        public Iterator(T[] dataArray) {
            this.dataArray = dataArray;
        }

        public boolean hasNext() {
            return position < dataArray.length;
        }

        public T next() {
            if (position == dataArray.length) {
                throw new NoSuchElementException("Out of elements: " + position);
            }

            return dataArray[position++];
        }

        public void remove() {
            throw new UnsupportedOperationException("Cannot remove element from an Array.");
        }
    }

    public static boolean isNullOrContainsNull(Object[] array) {
        if (null == array) {
            return true;
        }
        int count = array.length;
        for (int i = 0; i < count; ++i) {
            if (null == array[i]) {
                return true;
            }
        }
        return false;
    }
}