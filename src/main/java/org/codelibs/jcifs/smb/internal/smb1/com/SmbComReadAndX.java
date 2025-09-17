/* org.codelibs.jcifs.smb smb client library in Java
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
 * SMB1 Read AndX request message.
 *
 * This command is used to read data from a file that has been
 * previously opened with an Open command.
 */
public class SmbComReadAndX extends AndXServerMessageBlock {

    private long offset;
    private int fid;
    int openTimeout;
    int maxCount, minCount, remaining;

    /**
     * Constructs a Read AndX request.
     *
     * @param config the configuration
     */
    public SmbComReadAndX(final Configuration config) {
        super(config, SMB_COM_READ_ANDX);
        this.openTimeout = 0xFFFFFFFF;
    }

    /**
     * Constructs a Read AndX request with parameters.
     *
     * @param config the configuration
     * @param fid the file identifier
     * @param offset the file offset to read from
     * @param maxCount the maximum number of bytes to read
     * @param andx the next command in the chain
     */
    public SmbComReadAndX(final Configuration config, final int fid, final long offset, final int maxCount, final ServerMessageBlock andx) {
        super(config, SMB_COM_READ_ANDX, andx);
        this.fid = fid;
        this.offset = offset;
        this.maxCount = this.minCount = maxCount;
        this.openTimeout = 0xFFFFFFFF;
    }

    /**
     * Gets the maximum count of bytes to read.
     *
     * @return the maxCount
     */
    public final int getMaxCount() {
        return this.maxCount;
    }

    /**
     * Sets the maximum count of bytes to read.
     *
     * @param maxCount
     *            the maxCount to set
     */
    public final void setMaxCount(final int maxCount) {
        this.maxCount = maxCount;
    }

    /**
     * Gets the minimum count of bytes to read.
     *
     * @return the minCount
     */
    public final int getMinCount() {
        return this.minCount;
    }

    /**
     * Sets the minimum count of bytes to read.
     *
     * @param minCount
     *            the minCount to set
     */
    public final void setMinCount(final int minCount) {
        this.minCount = minCount;
    }

    /**
     * Gets the remaining bytes count.
     *
     * @return the remaining
     */
    public final int getRemaining() {
        return this.remaining;
    }

    /**
     * Sets the open timeout value.
     *
     * @param openTimeout
     *            the openTimeout to set
     */
    public final void setOpenTimeout(final int openTimeout) {
        this.openTimeout = openTimeout;
    }

    /**
     * Sets the remaining bytes count.
     *
     * @param remaining
     *            the remaining to set
     */
    public final void setRemaining(final int remaining) {
        this.remaining = remaining;
    }

    void setParam(final int fid, final long offset, final int maxCount) {
        this.fid = fid;
        this.offset = offset;
        this.maxCount = this.minCount = maxCount;
    }

    @Override
    protected int getBatchLimit(final Configuration cfg, final byte cmd) {
        return cmd == SMB_COM_CLOSE ? cfg.getBatchLimit("ReadAndX.Close") : 0;
    }

    @Override
    protected int writeParameterWordsWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        SMBUtil.writeInt2(this.fid, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt4(this.offset, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt2(this.maxCount, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.minCount, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt4(this.openTimeout, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt2(this.remaining, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt4(this.offset >> 32, dst, dstIndex);
        dstIndex += 4;

        return dstIndex - start;
    }

    @Override
    protected int writeBytesWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
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
        return ("SmbComReadAndX[" + super.toString() + ",fid=" + this.fid + ",offset=" + this.offset + ",maxCount=" + this.maxCount
                + ",minCount=" + this.minCount + ",openTimeout=" + this.openTimeout + ",remaining=" + this.remaining + ",offset="
                + this.offset + "]");
    }
}
