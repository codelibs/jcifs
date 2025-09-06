/*
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
 *                     "Christopher R. Hertel" <jcifs at samba dot org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package org.codelibs.jcifs.smb.util;

/**
 * Utility class for hexadecimal dumping of binary data.
 * This class provides methods for converting binary data to readable hex format.
 */

public class Hexdump {

    /**
     * Default constructor.
     */
    public Hexdump() {
        // Utility class - no instance variables to initialize
    }

    /**
     * Array of hexadecimal digit characters used for converting binary data to hex representation.
     */
    public static final char[] HEX_DIGITS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    /**
     * This is an alternative to the <code>java.lang.Integer.toHexString</code>
     * method. It is an efficient relative that also will pad the left side so
     * that the result is <code>size</code> digits.
     *
     * @param val the integer value to convert to hexadecimal
     * @param size the desired length of the resulting hex string (will be left-padded with zeros)
     * @return a hexadecimal string representation of the value, padded to the specified size
     */
    public static String toHexString(final int val, final int size) {
        final char[] c = new char[size];
        toHexChars(val, c, 0, size);
        return new String(c);
    }

    /**
     * Converts a long value to a hexadecimal string representation with specified padding.
     *
     * @param val the long value to convert to hexadecimal
     * @param size the desired length of the resulting hex string (will be left-padded with zeros)
     * @return a hexadecimal string representation of the value, padded to the specified size
     */
    public static String toHexString(final long val, final int size) {
        final char[] c = new char[size];
        toHexChars(val, c, 0, size);
        return new String(c);
    }

    /**
     * Converts a byte array to a hexadecimal string representation.
     *
     * @param src the source byte array to convert
     * @param srcIndex the starting index in the source array
     * @param size the number of bytes to convert from the source array
     * @return a hexadecimal string representation of the byte array
     */
    public static String toHexString(final byte[] src, final int srcIndex, final int size) {
        final char[] c = new char[2 * size];
        for (int i = 0, j = 0; i < size; i++) {
            c[j] = HEX_DIGITS[src[srcIndex + i] >> 4 & 0x0F];
            j++;
            c[j++] = HEX_DIGITS[src[srcIndex + i] & 0x0F];
        }
        return new String(c);
    }

    /**
     * Converts a byte array to a hexadecimal string representation.
     *
     * @param data the byte array to convert
     * @return a hexadecimal string representation of the entire byte array
     */
    public static String toHexString(final byte[] data) {
        return toHexString(data, 0, data.length);
    }

    /**
     * This is the same as {@link org.codelibs.jcifs.smb.util.Hexdump#toHexString(int val, int
     * size)} but provides a more practical form when trying to avoid {@link
     * java.lang.String} concatenation and {@link java.lang.StringBuffer}.
     *
     * @param val the integer value to convert to hexadecimal characters
     * @param dst the destination character array to write the hex digits into
     * @param dstIndex the starting index in the destination array
     * @param size the number of hex digits to write (will be left-padded with zeros)
     */
    public static void toHexChars(int val, final char dst[], final int dstIndex, int size) {
        while (size > 0) {
            final int i = dstIndex + size - 1;
            if (i < dst.length) {
                dst[i] = HEX_DIGITS[val & 0x000F];
            }
            if (val != 0) {
                val >>>= 4;
            }
            size--;
        }
    }

    /**
     * Converts a long value to hexadecimal characters and writes them to the specified character array.
     *
     * @param val the long value to convert to hexadecimal characters
     * @param dst the destination character array to write the hex digits into
     * @param dstIndex the starting index in the destination array
     * @param size the number of hex digits to write (will be left-padded with zeros)
     */
    public static void toHexChars(long val, final char dst[], final int dstIndex, int size) {
        while (size > 0) {
            dst[dstIndex + size - 1] = HEX_DIGITS[(int) (val & 0x000FL)];
            if (val != 0) {
                val >>>= 4;
            }
            size--;
        }
    }

}
