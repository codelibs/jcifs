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
package jcifs.pac;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Date;

import jcifs.SmbConstants;
import jcifs.smb.SID;

@SuppressWarnings("javadoc")
public class PacDataInputStream {

    private final DataInputStream dis;
    private final int size;

    public PacDataInputStream(final InputStream in) throws IOException {
        this.dis = new DataInputStream(in);
        this.size = in.available();
    }

    public void align(final int mask) throws IOException {
        final int position = this.size - this.dis.available();
        final int shift = position & mask - 1;
        if (mask != 0 && shift != 0) {
            this.dis.skip(mask - shift);
        }
    }

    public int available() throws IOException {
        return this.dis.available();
    }

    public void readFully(final byte[] b) throws IOException {
        this.dis.readFully(b);
    }

    public void readFully(final byte[] b, final int off, final int len) throws IOException {
        this.dis.readFully(b, off, len);
    }

    public char readChar() throws IOException {
        align(2);
        return this.dis.readChar();
    }

    public byte readByte() throws IOException {
        return this.dis.readByte();
    }

    public short readShort() throws IOException {
        align(2);
        return Short.reverseBytes(this.dis.readShort());
    }

    public int readInt() throws IOException {
        align(4);
        return Integer.reverseBytes(this.dis.readInt());
    }

    public long readLong() throws IOException {
        align(8);
        return Long.reverseBytes(this.dis.readLong());
    }

    public int readUnsignedByte() throws IOException {
        return readByte() & 0xff;
    }

    public long readUnsignedInt() throws IOException {
        return readInt() & 0xffffffffL;
    }

    public int readUnsignedShort() throws IOException {
        return readShort() & 0xffff;
    }

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

    public PacUnicodeString readUnicodeString() throws IOException, PACDecodingException {
        final short length = readShort();
        final short maxLength = readShort();
        final int pointer = readInt();

        if (maxLength < length) {
            throw new PACDecodingException("Malformed string in PAC");
        }

        return new PacUnicodeString(length, maxLength, pointer);
    }

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

    public SID readSid() throws IOException, PACDecodingException {
        final int sidSize = readInt();
        final byte[] bytes = new byte[8 + sidSize * 4];
        readFully(bytes);
        return new SID(bytes, 0);
    }

    public int skipBytes(final int n) throws IOException {
        return this.dis.skipBytes(n);
    }

}
