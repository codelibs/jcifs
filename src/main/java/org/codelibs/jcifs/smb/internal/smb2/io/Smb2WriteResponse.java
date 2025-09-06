/*
 * © 2017 AgNO3 Gmbh & Co. KG
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
package org.codelibs.jcifs.smb.internal.smb2.io;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Response;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2 Write response message.
 *
 * This response contains information about the write operation,
 * including the number of bytes actually written.
 *
 * @author mbechler
 */
public class Smb2WriteResponse extends ServerMessageBlock2Response {

    private int count;
    private int remaining;

    /**
     * Creates a new SMB2 write response.
     *
     * @param config the CIFS configuration
     */
    public Smb2WriteResponse(final Configuration config) {
        super(config);
    }

    /**
     * Returns the number of bytes written.
     *
     * @return the count
     */
    public final int getCount() {
        return this.count;
    }

    /**
     * Returns the number of bytes remaining to be written.
     *
     * @return the remaining
     */
    public final int getRemaining() {
        return this.remaining;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat(final byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException {
        final int start = bufferIndex;
        final int structureSize = SMBUtil.readInt2(buffer, bufferIndex);
        if (structureSize != 17) {
            throw new SMBProtocolDecodingException("Expected structureSize = 17");
        }
        bufferIndex += 4;

        this.count = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.remaining = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        bufferIndex += 4; // WriteChannelInfoOffset/WriteChannelInfoLength
        return bufferIndex - start;
    }

}
