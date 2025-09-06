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
 * SMB2 Read request message.
 *
 * This command is used to read data from a file that has been
 * previously opened with a Create request.
 *
 * @author mbechler
 */
public class Smb2ReadRequest extends ServerMessageBlock2Request<Smb2ReadResponse> implements RequestWithFileId {

    /**
     * Flag to indicate unbuffered read operation
     */
    public static byte SMB2_READFLAG_READ_UNBUFFERED = 0x1;
    /**
     * Channel type for standard read without RDMA
     */
    public static int SMB2_CHANNEL_NONE = 0x0;
    /**
     * Channel type for RDMA version 1
     */
    public static int SMB2_CHANNEL_RDMA_V1 = 0x1;
    /**
     * Channel type for RDMA version 1 with invalidate
     */
    public static int SMB2_CHANNEL_RDMA_V1_INVALIDATE = 0x2;

    private byte[] fileId;
    private final byte[] outputBuffer;
    private final int outputBufferOffset;
    private byte padding;
    private byte readFlags;
    private int readLength;
    private long offset;
    private int minimumCount;
    private int channel;
    private int remainingBytes;
    private RdmaChannelInfo rdmaChannelInfo;

    /**
     * Constructs a SMB2 read request with the specified parameters
     *
     * @param config
     *            the configuration to use for this request
     * @param fileId
     *            the file ID to read from
     * @param outputBuffer
     *            the buffer to read data into
     * @param outputBufferOffset
     *            the offset in the output buffer to start writing data
     */
    public Smb2ReadRequest(final Configuration config, final byte[] fileId, final byte[] outputBuffer, final int outputBufferOffset) {
        super(config, SMB2_READ);
        this.fileId = fileId;
        this.outputBuffer = outputBuffer;
        this.outputBufferOffset = outputBufferOffset;
    }

    @Override
    protected Smb2ReadResponse createResponse(final CIFSContext tc, final ServerMessageBlock2Request<Smb2ReadResponse> req) {
        return new Smb2ReadResponse(tc.getConfig(), this.outputBuffer, this.outputBufferOffset);
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

    /**
     * Sets the padding for the read request
     *
     * @param padding
     *            the padding to set
     */
    public void setPadding(final byte padding) {
        this.padding = padding;
    }

    /**
     * Sets the read flags for the read operation
     *
     * @param readFlags
     *            the readFlags to set
     */
    public void setReadFlags(final byte readFlags) {
        this.readFlags = readFlags;
    }

    /**
     * Sets the number of bytes to read
     *
     * @param readLength
     *            the readLength to set
     */
    public void setReadLength(final int readLength) {
        this.readLength = readLength;
    }

    /**
     * Sets the file offset from which to start reading
     *
     * @param offset
     *            the offset to set
     */
    public void setOffset(final long offset) {
        this.offset = offset;
    }

    /**
     * Sets the minimum number of bytes that must be read for the operation to succeed
     *
     * @param minimumCount
     *            the minimumCount to set
     */
    public void setMinimumCount(final int minimumCount) {
        this.minimumCount = minimumCount;
    }

    /**
     * Sets the number of bytes remaining to be read after this request
     *
     * @param remainingBytes
     *            the remainingBytes to set
     */
    public void setRemainingBytes(final int remainingBytes) {
        this.remainingBytes = remainingBytes;
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
     * Get the read length
     *
     * @return read length in bytes
     */
    public int getReadLength() {
        return readLength;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest#size()
     */
    @Override
    public int size() {
        return size8(Smb2Constants.SMB2_HEADER_LENGTH + 49);
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
        dst[dstIndex + 2] = this.padding;
        dst[dstIndex + 3] = this.readFlags;
        dstIndex += 4;
        SMBUtil.writeInt4(this.readLength, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt8(this.offset, dst, dstIndex);
        dstIndex += 8;
        System.arraycopy(this.fileId, 0, dst, dstIndex, 16);
        dstIndex += 16;
        SMBUtil.writeInt4(this.minimumCount, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.channel, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.remainingBytes, dst, dstIndex);
        dstIndex += 4;

        // ReadChannelInfo (Offset/Length for SMB2_RDMA_TRANSFORM)
        if (rdmaChannelInfo != null && channel == Smb2Constants.SMB2_CHANNEL_RDMA_V1) {
            // When using RDMA channel, this points to SMB2_RDMA_TRANSFORM in Buffer
            SMBUtil.writeInt2(80, dst, dstIndex); // ReadChannelInfoOffset (after header)
            SMBUtil.writeInt2(16, dst, dstIndex + 2); // ReadChannelInfoLength
            dstIndex += 4;
        } else {
            SMBUtil.writeInt2(0, dst, dstIndex);
            SMBUtil.writeInt2(0, dst, dstIndex + 2);
            dstIndex += 4;
        }

        // one byte in buffer must be zero
        dst[dstIndex] = 0;
        dstIndex += 1;

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
