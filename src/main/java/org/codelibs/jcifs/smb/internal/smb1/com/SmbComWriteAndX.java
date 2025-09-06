/*
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
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

package org.codelibs.jcifs.smb.internal.smb1.com;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.smb1.AndXServerMessageBlock;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB1 Write AndX request message.
 *
 * This command is used to write data to a file that has been
 * previously opened with an Open command.
 */
public class SmbComWriteAndX extends AndXServerMessageBlock {

    private int fid, remaining, dataLength, dataOffset, off;
    private byte[] b;
    private long offset;
    private int pad;
    private int writeMode;

    /**
     * Constructs an empty write AndX request.
     *
     * @param config the configuration to use
     */
    public SmbComWriteAndX(final Configuration config) {
        super(config, SMB_COM_WRITE_ANDX, null);
    }

    /**
     * Constructs a write AndX request to write data to a file.
     *
     * @param config the configuration to use
     * @param fid the file identifier
     * @param offset the file offset at which to write
     * @param remaining the number of bytes remaining to be written
     * @param b the data buffer containing bytes to write
     * @param off the offset in the buffer where data starts
     * @param len the number of bytes to write
     * @param andx the next command in the AndX chain, or null
     */
    public SmbComWriteAndX(final Configuration config, final int fid, final long offset, final int remaining, final byte[] b, final int off,
            final int len, final ServerMessageBlock andx) {
        super(config, SMB_COM_WRITE_ANDX, andx);
        this.fid = fid;
        this.offset = offset;
        this.remaining = remaining;
        this.b = b;
        this.off = off;
        this.dataLength = len;
    }

    /**
     * Sets the parameters for this write AndX request.
     *
     * @param fid the file identifier
     * @param offset the file offset at which to write
     * @param remaining the number of bytes remaining to be written
     * @param b the data buffer containing bytes to write
     * @param off the offset in the buffer where data starts
     * @param len the number of bytes to write
     */
    public final void setParam(final int fid, final long offset, final int remaining, final byte[] b, final int off, final int len) {
        this.fid = fid;
        this.offset = offset;
        this.remaining = remaining;
        this.b = b;
        this.off = off;
        this.dataLength = len;
        this.digest = null; /*
                             * otherwise recycled commands
                             * like writeandx will choke if session
                             * closes in between
                             */
    }

    /**
     * Sets the write mode flags for this request.
     *
     * @param writeMode
     *            the writeMode to set
     */
    public final void setWriteMode(final int writeMode) {
        this.writeMode = writeMode;
    }

    @Override
    protected int getBatchLimit(final Configuration cfg, final byte cmd) {
        if (cmd == SMB_COM_READ_ANDX) {
            return cfg.getBatchLimit("WriteAndX.ReadAndX");
        }
        if (cmd == SMB_COM_CLOSE) {
            return cfg.getBatchLimit("WriteAndX.Close");
        }
        return 0;
    }

    @Override
    protected int writeParameterWordsWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        this.dataOffset = dstIndex - this.headerStart + 26; // 26 = off from here to pad

        this.pad = (this.dataOffset - this.headerStart) % 4;
        this.pad = this.pad == 0 ? 0 : 4 - this.pad;
        this.dataOffset += this.pad;

        SMBUtil.writeInt2(this.fid, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt4(this.offset, dst, dstIndex);
        dstIndex += 4;
        for (int i = 0; i < 4; i++) {
            dst[dstIndex++] = (byte) 0xFF;
        }
        SMBUtil.writeInt2(this.writeMode, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.remaining, dst, dstIndex);
        dstIndex += 2;
        dst[dstIndex] = (byte) 0x00;
        dstIndex++;
        dst[dstIndex++] = (byte) 0x00;
        SMBUtil.writeInt2(this.dataLength, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.dataOffset, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt4(this.offset >> 32, dst, dstIndex);
        dstIndex += 4;

        return dstIndex - start;
    }

    @Override
    protected int writeBytesWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        while (this.pad-- > 0) {
            dst[dstIndex] = (byte) 0xEE;
            dstIndex++;
        }
        System.arraycopy(this.b, this.off, dst, dstIndex, this.dataLength);
        dstIndex += this.dataLength;

        return dstIndex - start;
    }

    @Override
    protected int readParameterWordsWireFormat(final byte[] buffer, final int bufferIndex) {
        return 0;
    }

    @Override
    protected int readBytesWireFormat(final byte[] buffer, final int bufferIndex) {
        return 0;
    }

    @Override
    public String toString() {
        return ("SmbComWriteAndX[" + super.toString() + ",fid=" + this.fid + ",offset=" + this.offset + ",writeMode=" + this.writeMode
                + ",remaining=" + this.remaining + ",dataLength=" + this.dataLength + ",dataOffset=" + this.dataOffset + "]");
    }
}
