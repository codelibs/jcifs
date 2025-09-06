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

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.smb2.RequestWithFileId;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Request;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.codelibs.jcifs.smb.internal.smb2.rdma.RdmaChannelInfo;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2 Write request message.
 *
 * This command is used to write data to a file that has been
 * previously opened with a Create request.
 *
 * @author mbechler
 */
public class Smb2WriteRequest extends ServerMessageBlock2Request<Smb2WriteResponse> implements RequestWithFileId {

    /**
     * The overhead size in bytes for an SMB2 write request packet.
     */
    public static final int OVERHEAD = Smb2Constants.SMB2_HEADER_LENGTH + 48;

    private byte[] data;
    private int dataOffset;
    private int dataLength;

    private byte[] fileId;
    private long offset;
    private int channel;
    private int remainingBytes;
    private int writeFlags;
    private RdmaChannelInfo rdmaChannelInfo;

    /**
     * Creates a new SMB2 write request for writing data to a file.
     *
     * @param config the CIFS configuration
     * @param fileId the file identifier for the target file
     */
    public Smb2WriteRequest(final Configuration config, final byte[] fileId) {
        super(config, SMB2_WRITE);
        this.fileId = fileId;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.RequestWithFileId#setFileId(byte[])
     */
    @Override
    public void setFileId(final byte[] fileId) {
        this.fileId = fileId;
    }

    @Override
    protected Smb2WriteResponse createResponse(final CIFSContext tc, final ServerMessageBlock2Request<Smb2WriteResponse> req) {
        return new Smb2WriteResponse(tc.getConfig());
    }

    /**
     * Sets the data to be written to the file.
     *
     * @param data the data buffer to write
     * @param offset the offset in the data buffer
     * @param length the number of bytes to write
     */
    public void setData(final byte[] data, final int offset, final int length) {
        this.data = data;
        this.dataOffset = offset;
        this.dataLength = length;
    }

    /**
     * Sets the number of bytes remaining to be written in a sequence of write operations.
     *
     * @param remainingBytes the remainingBytes to set
     */
    public void setRemainingBytes(final int remainingBytes) {
        this.remainingBytes = remainingBytes;
    }

    /**
     * Sets the write operation flags.
     *
     * @param writeFlags the writeFlags to set
     */
    public void setWriteFlags(final int writeFlags) {
        this.writeFlags = writeFlags;
    }

    /**
     * Sets the file offset where the write operation should begin.
     *
     * @param offset the offset to set
     */
    public void setOffset(final long offset) {
        this.offset = offset;
    }

    /**
     * Add RDMA channel information for direct memory access
     *
     * @param remoteKey remote memory key
     * @param address remote memory address
     * @param length length of memory region
     */
    public void addRdmaChannelInfo(int remoteKey, long address, int length) {
        this.rdmaChannelInfo = new RdmaChannelInfo(remoteKey, address, length);
        this.channel = Smb2Constants.SMB2_CHANNEL_RDMA_V1;
    }

    /**
     * Get RDMA channel information
     *
     * @return RDMA channel info, or null if not using RDMA
     */
    public RdmaChannelInfo getRdmaChannelInfo() {
        return rdmaChannelInfo;
    }

    /**
     * Get write data
     *
     * @return data to write
     */
    public byte[] getData() {
        return data;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest#size()
     */
    @Override
    public int size() {
        return size8(Smb2Constants.SMB2_HEADER_LENGTH + 48 + this.dataLength);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        SMBUtil.writeInt2(49, dst, dstIndex);
        final int dataOffsetOffset = dstIndex + 2;
        dstIndex += 4;
        SMBUtil.writeInt4(this.dataLength, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt8(this.offset, dst, dstIndex);
        dstIndex += 8;
        System.arraycopy(this.fileId, 0, dst, dstIndex, 16);
        dstIndex += 16;
        SMBUtil.writeInt4(this.channel, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.remainingBytes, dst, dstIndex);
        dstIndex += 4;

        // WriteChannelInfo (Offset/Length for SMB2_RDMA_TRANSFORM)
        if (rdmaChannelInfo != null && channel == Smb2Constants.SMB2_CHANNEL_RDMA_V1) {
            // Calculate offset for SMB2_RDMA_TRANSFORM after data
            int transformOffset = 112 + this.dataLength; // After header (64) + write req (48) + data
            SMBUtil.writeInt2(transformOffset, dst, dstIndex); // writeChannelInfoOffset
            SMBUtil.writeInt2(16, dst, dstIndex + 2); // writeChannelInfoLength (size of SMB2_RDMA_TRANSFORM)
        } else {
            SMBUtil.writeInt2(0, dst, dstIndex); // writeChannelInfoOffset
            SMBUtil.writeInt2(0, dst, dstIndex + 2); // writeChannelInfoLength
        }
        dstIndex += 4;

        SMBUtil.writeInt4(this.writeFlags, dst, dstIndex);
        dstIndex += 4;

        SMBUtil.writeInt2(dstIndex - getHeaderStart(), dst, dataOffsetOffset);

        if (dstIndex + this.dataLength > dst.length) {
            throw new IllegalArgumentException(
                    String.format("Data exceeds buffer size ( remain buffer: %d data length: %d)", dst.length - dstIndex, this.dataLength));
        }

        System.arraycopy(this.data, this.dataOffset, dst, dstIndex, this.dataLength);
        dstIndex += this.dataLength;

        // Write SMB2_RDMA_TRANSFORM if using RDMA channel
        if (rdmaChannelInfo != null && channel == Smb2Constants.SMB2_CHANNEL_RDMA_V1) {
            rdmaChannelInfo.encode(dst, dstIndex);
            dstIndex += 16;
        }

        return dstIndex - start;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat(final byte[] buffer, final int bufferIndex) {
        return 0;
    }

}
