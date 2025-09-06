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
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB1 Read AndX Response message.
 *
 * This response contains the data that was read from the file
 * along with information about the read operation.
 */
public class SmbComReadAndXResponse extends AndXServerMessageBlock {

    private byte[] data;
    private int offset, dataCompactionMode, dataLength, dataOffset;

    /**
     * Constructs a Read AndX response.
     *
     * @param config the configuration
     */
    public SmbComReadAndXResponse(final Configuration config) {
        super(config);
    }

    /**
     * Constructs a Read AndX response with buffer.
     *
     * @param config the configuration
     * @param b the data buffer
     * @param off the offset in the buffer
     */
    public SmbComReadAndXResponse(final Configuration config, final byte[] b, final int off) {
        super(config);
        this.data = b;
        this.offset = off;
    }

    void setParam(final byte[] b, final int off) {
        this.data = b;
        this.offset = off;
    }

    /**
     * Gets the read data buffer.
     *
     * @return the read data
     */
    public final byte[] getData() {
        return this.data;
    }

    /**
     * Gets the offset in the data buffer.
     *
     * @return the offset
     */
    public final int getOffset() {
        return this.offset;
    }

    /**
     * Adjusts the offset by the specified amount.
     *
     * @param n the amount to adjust the offset
     */
    public void adjustOffset(final int n) {
        this.offset += n;
    }

    /**
     * Gets the data length.
     *
     * @return the dataLength
     */
    public final int getDataLength() {
        return this.dataLength;
    }

    /**
     * Gets the data offset.
     *
     * @return the dataOffset
     */
    public final int getDataOffset() {
        return this.dataOffset;
    }

    @Override
    protected int writeParameterWordsWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    protected int writeBytesWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    protected int readParameterWordsWireFormat(final byte[] buffer, int bufferIndex) {
        final int start = bufferIndex;

        bufferIndex += 2; // reserved
        this.dataCompactionMode = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 4; // 2 reserved
        this.dataLength = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.dataOffset = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 12; // 10 reserved

        return bufferIndex - start;
    }

    @Override
    protected int readBytesWireFormat(final byte[] buffer, final int bufferIndex) {
        // handled special in SmbTransport.doRecv()
        return 0;
    }

    @Override
    public String toString() {
        return ("SmbComReadAndXResponse[" + super.toString() + ",dataCompactionMode=" + this.dataCompactionMode + ",dataLength="
                + this.dataLength + ",dataOffset=" + this.dataOffset + "]");
    }

}
