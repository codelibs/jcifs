/*
 * © 2016 AgNO3 Gmbh & Co. KG
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
package org.codelibs.jcifs.smb.internal.util;

import org.codelibs.jcifs.smb.SmbConstants;

/**
 * SMB protocol utility class providing low-level data encoding and decoding operations.
 * Contains methods for reading and writing various data types (integers, strings, timestamps)
 * in SMB protocol format, handling endianness and data type conversions.
 *
 * @author mbechler
 */
public class SMBUtil {

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private SMBUtil() {
    }

    /**
     * Writes a 16-bit integer value to a byte array in little-endian format
     * @param val the value to write
     * @param dst the destination byte array
     * @param dstIndex the starting index in the destination array
     */
    public static void writeInt2(final long val, final byte[] dst, int dstIndex) {
        dst[dstIndex] = (byte) val;
        dstIndex++;
        dst[dstIndex] = (byte) (val >> 8);
    }

    /**
     * Writes a 32-bit integer value to a byte array in little-endian format
     * @param val the value to write
     * @param dst the destination byte array
     * @param dstIndex the starting index in the destination array
     */
    public static void writeInt4(long val, final byte[] dst, int dstIndex) {
        dst[dstIndex] = (byte) val;
        dst[dstIndex + 1] = (byte) (val >> 8);
        dst[dstIndex + 2] = (byte) (val >> 16);
        dst[dstIndex + 3] = (byte) (val >> 24);
    }

    /**
     * Reads a 16-bit integer value from a byte array in little-endian format
     * @param src the source byte array
     * @param srcIndex the starting index in the source array
     * @return the 16-bit integer value
     */
    public static int readInt2(final byte[] src, final int srcIndex) {
        return (src[srcIndex] & 0xFF) + ((src[srcIndex + 1] & 0xFF) << 8);
    }

    /**
     * Reads a 32-bit integer value from a byte array in little-endian format
     * @param src the source byte array
     * @param srcIndex the starting index in the source array
     * @return the 32-bit integer value
     */
    public static int readInt4(final byte[] src, final int srcIndex) {
        return (src[srcIndex] & 0xFF) + ((src[srcIndex + 1] & 0xFF) << 8) + ((src[srcIndex + 2] & 0xFF) << 16)
                + ((src[srcIndex + 3] & 0xFF) << 24);
    }

    /**
     * Reads a 64-bit integer value from a byte array in little-endian format
     * @param src the source byte array
     * @param srcIndex the starting index in the source array
     * @return the 64-bit integer value
     */
    public static long readInt8(final byte[] src, final int srcIndex) {
        return (readInt4(src, srcIndex) & 0xFFFFFFFFL) + ((long) readInt4(src, srcIndex + 4) << 32);
    }

    /**
     * Writes a 64-bit integer value to a byte array in little-endian format
     * @param val the value to write
     * @param dst the destination byte array
     * @param dstIndex the starting index in the destination array
     */
    public static void writeInt8(long val, final byte[] dst, int dstIndex) {
        dst[dstIndex] = (byte) val;
        dst[dstIndex + 1] = (byte) (val >> 8);
        dst[dstIndex + 2] = (byte) (val >> 16);
        dst[dstIndex + 3] = (byte) (val >> 24);
        dst[dstIndex + 4] = (byte) (val >> 32);
        dst[dstIndex + 5] = (byte) (val >> 40);
        dst[dstIndex + 6] = (byte) (val >> 48);
        dst[dstIndex + 7] = (byte) (val >> 56);
    }

    /**
     * Reads a Windows FILETIME value and converts it to Java time in milliseconds
     * @param src the source byte array
     * @param srcIndex the starting index in the source array
     * @return the time value in milliseconds since January 1, 1970 UTC
     */
    public static long readTime(final byte[] src, final int srcIndex) {
        final int low = readInt4(src, srcIndex);
        final int hi = readInt4(src, srcIndex + 4);
        long t = (long) hi << 32L | low & 0xFFFFFFFFL;
        return t / 10000L - SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601;
    }

    /**
     * Writes a Java time value as a Windows FILETIME
     * @param t the time value in milliseconds since January 1, 1970 UTC
     * @param dst the destination byte array
     * @param dstIndex the starting index in the destination array
     */
    public static void writeTime(long t, final byte[] dst, final int dstIndex) {
        if (t != 0L) {
            t = (t + SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601) * 10000L;
        }
        writeInt8(t, dst, dstIndex);
    }

    /**
     * Reads a Unix time value (32-bit seconds) and converts it to Java time in milliseconds
     * @param buffer the source byte array
     * @param bufferIndex the starting index in the source array
     * @return the time value in milliseconds since January 1, 1970 UTC
     */
    public static long readUTime(final byte[] buffer, final int bufferIndex) {
        return (readInt4(buffer, bufferIndex) & 0xFFFFFFFFL) * 1000L;
    }

    /**
     * Writes a Java time value as a Unix time (32-bit seconds)
     * @param t the time value in milliseconds since January 1, 1970 UTC
     * @param dst the destination byte array
     * @param dstIndex the starting index in the destination array
     */
    public static void writeUTime(final long t, final byte[] dst, final int dstIndex) {
        writeInt4(t / 1000, dst, dstIndex);
    }

    /**
     * SMB1 protocol header template with magic number 0xFF 'SMB'
     */
    public static final byte[] SMB_HEADER = { (byte) 0xFF, (byte) 'S', (byte) 'M', (byte) 'B', (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };

    /**
     * SMB2 protocol header template with magic number 0xFE 'SMB'
     */
    public static final byte[] SMB2_HEADER = { (byte) 0xFE, (byte) 'S', (byte) 'M', (byte) 'B', // ProtocolId
            (byte) 64, (byte) 0x00, // StructureSize (LE)
            (byte) 0x00, (byte) 0x00, // CreditCharge (reserved 2.0.2)
            (byte) 0x00, (byte) 0x00, // ChannelSequence
            (byte) 0x00, (byte) 0x00, // Reserved
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // Status
            (byte) 0x00, (byte) 0x00, // Command
            (byte) 0x00, (byte) 0x00, // CreditRequest/CreditResponse
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // Flags
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // NextCommand
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // MessageId
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // Reserved / AsyncId
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // TreeId / AsyncId
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // SessionId
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // Signature
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // Signature
                                                                                                                    // (cont)
    };

}
