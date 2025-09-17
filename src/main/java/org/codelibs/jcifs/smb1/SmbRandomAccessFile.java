/* org.codelibs.jcifs.smb smb client library in Java
 * Copyright (C) 2003  "Michael B. Allen" <jcifs at samba dot org>
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

package org.codelibs.jcifs.smb1;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.UnknownHostException;

import org.codelibs.jcifs.smb1.util.Encdec;

/**
 * This class provides random access to files stored on an SMB/CIFS network resource.
 * It implements the DataInput and DataOutput interfaces for reading and writing primitive
 * Java data types to the file.
 */
public class SmbRandomAccessFile implements DataOutput, DataInput {

    private static final int WRITE_OPTIONS = 0x0842;

    private final SmbFile file;
    private long fp;
    private int openFlags, access = 0;

    private final int readSize;

    private final int writeSize;

    private int ch;

    private int options = 0;
    private final byte[] tmp = new byte[8];
    private SmbComWriteAndXResponse write_andx_resp = null;

    /**
     * Constructs an SmbRandomAccessFile with the specified URL, mode, and share access flags.
     *
     * @param url the SMB URL of the file to access
     * @param mode the access mode ("r" for read-only, "rw" for read-write)
     * @param shareAccess the share access flags for file sharing
     * @throws SmbException if an SMB error occurs
     * @throws MalformedURLException if the URL is malformed
     * @throws UnknownHostException if the host cannot be resolved
     */
    public SmbRandomAccessFile(final String url, final String mode, final int shareAccess)
            throws SmbException, MalformedURLException, UnknownHostException {
        this(new SmbFile(url, "", null, shareAccess), mode);
    }

    /**
     * Constructs an SmbRandomAccessFile from an existing SmbFile with the specified access mode.
     *
     * @param file the SmbFile to access
     * @param mode the access mode ("r" for read-only, "rw" for read-write)
     * @throws SmbException if an SMB error occurs
     * @throws MalformedURLException if the URL is malformed
     * @throws UnknownHostException if the host cannot be resolved
     */
    public SmbRandomAccessFile(final SmbFile file, final String mode) throws SmbException, MalformedURLException, UnknownHostException {
        this.file = file;
        if (mode.equals("r")) {
            this.openFlags = SmbFile.O_CREAT | SmbFile.O_RDONLY;
        } else if (mode.equals("rw")) {
            this.openFlags = SmbFile.O_CREAT | SmbFile.O_RDWR | SmbFile.O_APPEND;
            write_andx_resp = new SmbComWriteAndXResponse();
            options = WRITE_OPTIONS;
            access = SmbConstants.FILE_READ_DATA | SmbConstants.FILE_WRITE_DATA;
        } else {
            throw new IllegalArgumentException("Invalid mode");
        }
        file.open(openFlags, access, SmbFile.ATTR_NORMAL, options);
        readSize = file.tree.session.transport.rcv_buf_size - 70;
        writeSize = file.tree.session.transport.snd_buf_size - 70;
        fp = 0L;
    }

    /**
     * Reads a single byte from the file at the current file pointer position.
     *
     * @return the byte read as an integer (0-255), or -1 if end of file is reached
     * @throws SmbException if an I/O error occurs
     */
    public int read() throws SmbException {
        if (read(tmp, 0, 1) == -1) {
            return -1;
        }
        return tmp[0] & 0xFF;
    }

    /**
     * Reads bytes from the file into the specified byte array.
     *
     * @param b the byte array to read data into
     * @return the number of bytes read, or -1 if end of file is reached
     * @throws SmbException if an I/O error occurs
     */
    public int read(final byte b[]) throws SmbException {
        return read(b, 0, b.length);
    }

    /**
     * Reads up to len bytes from the file into the specified byte array.
     *
     * @param b the byte array to read data into
     * @param off the offset in the array at which to start storing bytes
     * @param len the maximum number of bytes to read
     * @return the number of bytes read, or -1 if end of file is reached
     * @throws SmbException if an I/O error occurs
     */
    public int read(final byte b[], final int off, int len) throws SmbException {
        if (len <= 0) {
            return 0;
        }
        final long start = fp;

        // ensure file is open
        if (!file.isOpen()) {
            file.open(openFlags, 0, SmbFile.ATTR_NORMAL, options);
        }

        int r, n;
        final SmbComReadAndXResponse response = new SmbComReadAndXResponse(b, off);
        do {
            r = len > readSize ? readSize : len;
            file.send(new SmbComReadAndX(file.fid, fp, r, null), response);
            n = response.dataLength;
            if (n <= 0) {
                return (int) (fp - start > 0L ? fp - start : -1);
            }
            fp += n;
            len -= n;
            response.off += n;
        } while (len > 0 && n == r);

        return (int) (fp - start);
    }

    @Override
    public final void readFully(final byte b[]) throws SmbException {
        readFully(b, 0, b.length);
    }

    @Override
    public final void readFully(final byte b[], final int off, final int len) throws SmbException {
        int n = 0, count;

        do {
            count = this.read(b, off + n, len - n);
            if (count < 0) {
                throw new SmbException("EOF");
            }
            n += count;
            fp += count;
        } while (n < len);
    }

    @Override
    public int skipBytes(final int n) throws SmbException {
        if (n > 0) {
            fp += n;
            return n;
        }
        return 0;
    }

    @Override
    public void write(final int b) throws SmbException {
        tmp[0] = (byte) b;
        write(tmp, 0, 1);
    }

    @Override
    public void write(final byte b[]) throws SmbException {
        write(b, 0, b.length);
    }

    @Override
    public void write(final byte b[], int off, int len) throws SmbException {
        if (len <= 0) {
            return;
        }

        // ensure file is open
        if (!file.isOpen()) {
            file.open(openFlags, 0, SmbFile.ATTR_NORMAL, options);
        }

        int w;
        do {
            w = len > writeSize ? writeSize : len;
            file.send(new SmbComWriteAndX(file.fid, fp, len - w, b, off, w, null), write_andx_resp);
            fp += write_andx_resp.count;
            len -= write_andx_resp.count;
            off += write_andx_resp.count;
        } while (len > 0);
    }

    /**
     * Returns the current position of the file pointer.
     *
     * @return the current file pointer position
     * @throws SmbException if an I/O error occurs
     */
    public long getFilePointer() throws SmbException {
        return fp;
    }

    /**
     * Sets the file pointer to the specified position.
     *
     * @param pos the new file pointer position
     * @throws SmbException if an I/O error occurs
     */
    public void seek(final long pos) throws SmbException {
        fp = pos;
    }

    /**
     * Returns the length of the file.
     *
     * @return the file length in bytes
     * @throws SmbException if an I/O error occurs
     */
    public long length() throws SmbException {
        return file.length();
    }

    /**
     * Sets the length of the file. The file will be truncated or extended as necessary.
     *
     * @param newLength the new file length in bytes
     * @throws SmbException if an I/O error occurs
     */
    public void setLength(final long newLength) throws SmbException {
        // ensure file is open
        if (!file.isOpen()) {
            file.open(openFlags, 0, SmbFile.ATTR_NORMAL, options);
        }
        final SmbComWriteResponse rsp = new SmbComWriteResponse();
        file.send(new SmbComWrite(file.fid, (int) (newLength & 0xFFFFFFFFL), 0, tmp, 0, 0), rsp);
    }

    /**
     * Closes the file and releases any system resources associated with it.
     *
     * @throws SmbException if an I/O error occurs
     */
    public void close() throws SmbException {
        file.close();
    }

    @Override
    public final boolean readBoolean() throws SmbException {
        if (read(tmp, 0, 1) < 0) {
            throw new SmbException("EOF");
        }
        return tmp[0] != (byte) 0x00;
    }

    @Override
    public final byte readByte() throws SmbException {
        if (read(tmp, 0, 1) < 0) {
            throw new SmbException("EOF");
        }
        return tmp[0];
    }

    @Override
    public final int readUnsignedByte() throws SmbException {
        if (read(tmp, 0, 1) < 0) {
            throw new SmbException("EOF");
        }
        return tmp[0] & 0xFF;
    }

    @Override
    public final short readShort() throws SmbException {
        if (read(tmp, 0, 2) < 0) {
            throw new SmbException("EOF");
        }
        return Encdec.dec_uint16be(tmp, 0);
    }

    @Override
    public final int readUnsignedShort() throws SmbException {
        if (read(tmp, 0, 2) < 0) {
            throw new SmbException("EOF");
        }
        return Encdec.dec_uint16be(tmp, 0) & 0xFFFF;
    }

    @Override
    public final char readChar() throws SmbException {
        if (read(tmp, 0, 2) < 0) {
            throw new SmbException("EOF");
        }
        return (char) Encdec.dec_uint16be(tmp, 0);
    }

    @Override
    public final int readInt() throws SmbException {
        if (read(tmp, 0, 4) < 0) {
            throw new SmbException("EOF");
        }
        return Encdec.dec_uint32be(tmp, 0);
    }

    @Override
    public final long readLong() throws SmbException {
        if (read(tmp, 0, 8) < 0) {
            throw new SmbException("EOF");
        }
        return Encdec.dec_uint64be(tmp, 0);
    }

    @Override
    public final float readFloat() throws SmbException {
        if (read(tmp, 0, 4) < 0) {
            throw new SmbException("EOF");
        }
        return Encdec.dec_floatbe(tmp, 0);
    }

    @Override
    public final double readDouble() throws SmbException {
        if (read(tmp, 0, 8) < 0) {
            throw new SmbException("EOF");
        }
        return Encdec.dec_doublebe(tmp, 0);
    }

    @Override
    public final String readLine() throws SmbException {
        final StringBuilder input = new StringBuilder();
        int c = -1;
        boolean eol = false;

        while (!eol) {
            switch (c = read()) {
            case -1:
            case '\n':
                eol = true;
                break;
            case '\r':
                eol = true;
                final long cur = fp;
                if (read() != '\n') {
                    fp = cur;
                }
                break;
            default:
                input.append((char) c);
                break;
            }
        }

        if (c == -1 && input.length() == 0) {
            return null;
        }

        return input.toString();
    }

    @Override
    public final String readUTF() throws SmbException {
        final int size = readUnsignedShort();
        final byte[] b = new byte[size];
        read(b, 0, size);
        try {
            return Encdec.dec_utf8(b, 0, size);
        } catch (final IOException ioe) {
            throw new SmbException("", ioe);
        }
    }

    @Override
    public final void writeBoolean(final boolean v) throws SmbException {
        tmp[0] = (byte) (v ? 1 : 0);
        write(tmp, 0, 1);
    }

    @Override
    public final void writeByte(final int v) throws SmbException {
        tmp[0] = (byte) v;
        write(tmp, 0, 1);
    }

    @Override
    public final void writeShort(final int v) throws SmbException {
        Encdec.enc_uint16be((short) v, tmp, 0);
        write(tmp, 0, 2);
    }

    @Override
    public final void writeChar(final int v) throws SmbException {
        Encdec.enc_uint16be((short) v, tmp, 0);
        write(tmp, 0, 2);
    }

    @Override
    public final void writeInt(final int v) throws SmbException {
        Encdec.enc_uint32be(v, tmp, 0);
        write(tmp, 0, 4);
    }

    @Override
    public final void writeLong(final long v) throws SmbException {
        Encdec.enc_uint64be(v, tmp, 0);
        write(tmp, 0, 8);
    }

    @Override
    public final void writeFloat(final float v) throws SmbException {
        Encdec.enc_floatbe(v, tmp, 0);
        write(tmp, 0, 4);
    }

    @Override
    public final void writeDouble(final double v) throws SmbException {
        Encdec.enc_doublebe(v, tmp, 0);
        write(tmp, 0, 8);
    }

    @Override
    public final void writeBytes(final String s) throws SmbException {
        final byte[] b = s.getBytes();
        write(b, 0, b.length);
    }

    @Override
    public final void writeChars(final String s) throws SmbException {
        final int clen = s.length();
        final int blen = 2 * clen;
        final byte[] b = new byte[blen];
        final char[] c = new char[clen];
        s.getChars(0, clen, c, 0);
        for (int i = 0, j = 0; i < clen; i++) {
            b[j] = (byte) (c[i] >>> 8);
            j++;
            b[j++] = (byte) (c[i] >>> 0);
        }
        write(b, 0, blen);
    }

    @Override
    public final void writeUTF(final String str) throws SmbException {
        final int len = str.length();
        int ch, size = 0;
        byte[] dst;

        for (int i = 0; i < len; i++) {
            ch = str.charAt(i);
            size += ch > 0x07F ? ch > 0x7FF ? 3 : 2 : 1;
        }
        dst = new byte[size];
        writeShort(size);
        try {
            Encdec.enc_utf8(str, dst, 0, size);
        } catch (final IOException ioe) {
            throw new SmbException("", ioe);
        }
        write(dst, 0, size);
    }
}
