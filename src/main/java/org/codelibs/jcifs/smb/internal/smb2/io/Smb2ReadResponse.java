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
import org.codelibs.jcifs.smb.impl.NtStatus;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Response;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2 Read response message.
 *
 * This response contains the data that was read from the file
 * along with information about the read operation.
 *
 * @author mbechler
 */
public class Smb2ReadResponse extends ServerMessageBlock2Response {

    /**
     * Protocol overhead size for SMB2 read response
     */
    public static final int OVERHEAD = Smb2Constants.SMB2_HEADER_LENGTH + 16;

    private int dataRemaining;
    private int dataLength;
    private final byte[] outputBuffer;
    private final int outputBufferOffset;

    /**
     * Constructs a SMB2 read response with the specified configuration and output buffer
     *
     * @param config
     *            the configuration to use for this response
     * @param outputBuffer
     *            the buffer to receive the read data
     * @param outputBufferOffset
     *            the offset in the output buffer to start writing data
     */
    public Smb2ReadResponse(final Configuration config, final byte[] outputBuffer, final int outputBufferOffset) {
        super(config);
        this.outputBuffer = outputBuffer;
        this.outputBufferOffset = outputBufferOffset;
    }

    /**
     * Gets the number of bytes actually read
     *
     * @return the dataLength
     */
    public int getDataLength() {
        return this.dataLength;
    }

    /**
     * Gets the number of bytes remaining to be read
     *
     * @return the dataRemaining
     */
    public int getDataRemaining() {
        return this.dataRemaining;
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
        if (structureSize == 9) {
            return this.readErrorResponse(buffer, bufferIndex);
        }
        if (structureSize != 17) {
            throw new SMBProtocolDecodingException("Expected structureSize = 17");
        }

        final short dataOffset = buffer[bufferIndex + 2];
        bufferIndex += 4;
        this.dataLength = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.dataRemaining = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        bufferIndex += 4; // Reserved2

        final int dataStart = getHeaderStart() + dataOffset;

        if (this.dataLength + this.outputBufferOffset > this.outputBuffer.length) {
            throw new SMBProtocolDecodingException("Buffer to small for read response");
        }
        System.arraycopy(buffer, dataStart, this.outputBuffer, this.outputBufferOffset, this.dataLength);
        bufferIndex = Math.max(bufferIndex, dataStart + this.dataLength);
        return bufferIndex - start;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#isErrorResponseStatus()
     */
    @Override
    protected boolean isErrorResponseStatus() {
        return getStatus() != NtStatus.NT_STATUS_BUFFER_OVERFLOW && super.isErrorResponseStatus();
    }

}
