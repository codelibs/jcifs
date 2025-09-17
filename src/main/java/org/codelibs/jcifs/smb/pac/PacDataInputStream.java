/*
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
package org.codelibs.jcifs.smb.pac;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Date;

import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.impl.SID;

/**
 * Input stream for reading PAC data structures with proper alignment and byte ordering.
 * Handles little-endian byte order and data alignment requirements of PAC structures.
 */
public class PacDataInputStream {

    private final DataInputStream dis;
    private final int size;

    /**
     * Constructs a PAC data input stream from the given input stream.
     * @param in the underlying input stream
     * @throws IOException if an I/O error occurs
     */
    public PacDataInputStream(final InputStream in) throws IOException {
        this.dis = new DataInputStream(in);
        this.size = in.available();
    }

    /**
     * Aligns the stream position to the specified boundary.
     * @param mask the alignment mask (typically 2, 4, or 8)
     * @throws IOException if an I/O error occurs
     */
    public void align(final int mask) throws IOException {
        final int position = this.size - this.dis.available();
        final int shift = position & mask - 1;
        if (mask != 0 && shift != 0) {
            this.dis.skip(mask - shift);
        }
    }

    /**
     * Returns the number of bytes available to read.
     * @return the number of available bytes
     * @throws IOException if an I/O error occurs
     */
    public int available() throws IOException {
        return this.dis.available();
    }

    /**
     * Reads bytes into the specified array.
     * @param b the byte array to read into
     * @throws IOException if an I/O error occurs
     */
    public void readFully(final byte[] b) throws IOException {
        this.dis.readFully(b);
    }

    /**
     * Reads bytes into the specified array at the given offset.
     * @param b the byte array to read into
     * @param off the start offset in the array
     * @param len the number of bytes to read
     * @throws IOException if an I/O error occurs
     */
    public void readFully(final byte[] b, final int off, final int len) throws IOException {
        this.dis.readFully(b, off, len);
    }

    /**
     * Reads a 16-bit character value with proper alignment.
     * @return the character value
     * @throws IOException if an I/O error occurs
     */
    public char readChar() throws IOException {
        align(2);
        return this.dis.readChar();
    }

    /**
     * Reads a single byte value.
     * @return the byte value
     * @throws IOException if an I/O error occurs
     */
    public byte readByte() throws IOException {
        return this.dis.readByte();
    }

    /**
     * Reads a 16-bit short value with proper alignment and byte order.
     * @return the short value in little-endian format
     * @throws IOException if an I/O error occurs
     */
    public short readShort() throws IOException {
        align(2);
        return Short.reverseBytes(this.dis.readShort());
    }

    /**
     * Reads a 32-bit integer value with proper alignment and byte order.
     * @return the integer value in little-endian format
     * @throws IOException if an I/O error occurs
     */
    public int readInt() throws IOException {
        align(4);
        return Integer.reverseBytes(this.dis.readInt());
    }

    /**
     * Reads a 64-bit long value with proper alignment and byte order.
     * @return the long value in little-endian format
     * @throws IOException if an I/O error occurs
     */
    public long readLong() throws IOException {
        align(8);
        return Long.reverseBytes(this.dis.readLong());
    }

    /**
     * Reads an unsigned byte value.
     * @return the unsigned byte value as an integer
     * @throws IOException if an I/O error occurs
     */
    public int readUnsignedByte() throws IOException {
        return readByte() & 0xff;
    }

    /**
     * Reads an unsigned 32-bit integer value.
     * @return the unsigned integer value as a long
     * @throws IOException if an I/O error occurs
     */
    public long readUnsignedInt() throws IOException {
        return readInt() & 0xffffffffL;
    }

    /**
     * Reads an unsigned 16-bit short value.
     * @return the unsigned short value as an integer
     * @throws IOException if an I/O error occurs
     */
    public int readUnsignedShort() throws IOException {
        return readShort() & 0xffff;
    }

    /**
     * Reads a Windows FILETIME value and converts it to a Date.
     * @return the Date object, or null if the time represents infinity
     * @throws IOException if an I/O error occurs
     */
    public Date readFiletime() throws IOException {
        Date date = null;

        final long last = readUnsignedInt();
        final long first = readUnsignedInt();
        if (first != 0x7fffffffL && last != 0xffffffffL) {
            final BigInteger lastBigInt = BigInteger.valueOf(last);
            final BigInteger firstBigInt = BigInteger.valueOf(first);
            BigInteger completeBigInt = lastBigInt.add(firstBigInt.shiftLeft(32));
            completeBigInt = completeBigInt.divide(BigInteger.valueOf(10000L));
            completeBigInt = completeBigInt.add(BigInteger.valueOf(-SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601));
            date = new Date(completeBigInt.longValue());
        }

        return date;
    }

    /**
     * Reads a PAC Unicode string structure.
     * @return the PAC Unicode string object
     * @throws IOException if an I/O error occurs
     * @throws PACDecodingException if the string structure is malformed
     */
    public PacUnicodeString readUnicodeString() throws IOException, PACDecodingException {
        final short length = readShort();
        final short maxLength = readShort();
        final int pointer = readInt();

        if (maxLength < length) {
            throw new PACDecodingException("Malformed string in PAC");
        }

        return new PacUnicodeString(length, maxLength, pointer);
    }

    /**
     * Reads a string with length prefix from the stream.
     * @return the decoded string
     * @throws IOException if an I/O error occurs
     * @throws PACDecodingException if the string structure is malformed
     */
    public String readString() throws IOException, PACDecodingException {
        final int totalChars = readInt();
        final int unusedChars = readInt();
        final int usedChars = readInt();

        if (unusedChars > totalChars || usedChars > totalChars - unusedChars) {
            throw new PACDecodingException("Malformed string in PAC");
        }

        this.dis.skip(unusedChars * 2);
        final char[] chars = new char[usedChars];
        for (int l = 0; l < usedChars; l++) {
            chars[l] = (char) readShort();
        }

        return new String(chars);
    }

    /**
     * Reads a 32-bit RID and constructs a SID from it.
     * @return the constructed SID object
     * @throws IOException if an I/O error occurs
     * @throws PACDecodingException if the SID data is invalid
     */
    public SID readId() throws IOException, PACDecodingException {
        final byte[] bytes = new byte[4];
        readFully(bytes);

        final byte[] sidBytes = new byte[8 + bytes.length];
        sidBytes[0] = 1;
        sidBytes[1] = (byte) (bytes.length / 4);
        System.arraycopy(new byte[] { 0, 0, 0, 0, 0, 5 }, 0, sidBytes, 2, 6);
        System.arraycopy(bytes, 0, sidBytes, 8, bytes.length);

        return new SID(sidBytes, 0);
    }

    /**
     * Reads a full Security Identifier (SID) structure.
     * @return the SID object
     * @throws IOException if an I/O error occurs
     * @throws PACDecodingException if the SID data is invalid
     */
    public SID readSid() throws IOException, PACDecodingException {
        final int sidSize = readInt();
        final byte[] bytes = new byte[8 + sidSize * 4];
        readFully(bytes);
        return new SID(bytes, 0);
    }

    /**
     * Skips the specified number of bytes in the stream.
     * @param n the number of bytes to skip
     * @return the actual number of bytes skipped
     * @throws IOException if an I/O error occurs
     */
    public int skipBytes(final int n) throws IOException {
        return this.dis.skipBytes(n);
    }

}
