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
package jcifs.internal.smb2.ioctl;

import jcifs.Decodable;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;

/**
 * SMB2 SRV_COPYCHUNK_COPY response data structure. This structure contains the result
 * of a server-side copy operation.
 *
 * @author mbechler
 *
 */
public class SrvCopyChunkCopyResponse implements Decodable {

    /**
     * Constructs a new SrvCopyChunkCopyResponse.
     * This response contains the results of a server-side copy operation.
     */
    public SrvCopyChunkCopyResponse() {
    }

    private int chunksWritten;
    private int chunkBytesWritten;
    private int totalBytesWritten;

    /**
     * Gets the number of bytes written in the last chunk
     * @return the chunkBytesWritten
     */
    public int getChunkBytesWritten() {
        return this.chunkBytesWritten;
    }

    /**
     * Gets the number of chunks successfully written
     * @return the chunksWritten
     */
    public int getChunksWritten() {
        return this.chunksWritten;
    }

    /**
     * Gets the total number of bytes written in the copy operation
     * @return the totalBytesWritten
     */
    public int getTotalBytesWritten() {
        return this.totalBytesWritten;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Decodable#decode(byte[], int, int)
     */
    @Override
    public int decode(final byte[] buffer, int bufferIndex, final int len) throws SMBProtocolDecodingException {
        final int start = bufferIndex;
        this.chunksWritten = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.chunkBytesWritten = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.totalBytesWritten = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        return bufferIndex - start;
    }

}
