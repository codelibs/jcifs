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
package org.codelibs.jcifs.smb.internal.smb2.ioctl;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.Decodable;
import org.codelibs.jcifs.smb.NtStatus;
import org.codelibs.jcifs.smb.SmbException;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.dfs.DfsReferralResponseBuffer;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Response;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2 IOCTL response message. This response contains the result of a device control
 * operation on the server.
 *
 * @author mbechler
 *
 */
public class Smb2IoctlResponse extends ServerMessageBlock2Response {

    private final byte[] outputBuffer;
    private int ctlCode;
    private byte[] fileId;
    private int ioctlFlags;
    private Decodable outputData;
    private Decodable inputData;
    private int outputLength;

    /**
     * Constructs an SMB2 IOCTL response with the given configuration.
     *
     * @param config the configuration for this response
     */
    public Smb2IoctlResponse(final Configuration config) {
        super(config);
        this.outputBuffer = null;
    }

    /**
     * Constructs an SMB2 IOCTL response with the given configuration and output buffer.
     *
     * @param config the configuration for this response
     * @param outputBuffer the buffer to receive output data
     */
    public Smb2IoctlResponse(final Configuration config, final byte[] outputBuffer) {
        super(config);
        this.outputBuffer = outputBuffer;
    }

    /**
     * Constructs an SMB2 IOCTL response with the given configuration, output buffer and control code.
     *
     * @param config the configuration for this response
     * @param outputBuffer the buffer to receive output data
     * @param ctlCode the IOCTL control code
     */
    public Smb2IoctlResponse(final Configuration config, final byte[] outputBuffer, final int ctlCode) {
        super(config);
        this.outputBuffer = outputBuffer;
        this.ctlCode = ctlCode;
    }

    /**
     * Gets the IOCTL control code from the response.
     *
     * @return the ctlCode
     */
    public int getCtlCode() {
        return this.ctlCode;
    }

    /**
     * Gets the IOCTL flags from the response.
     *
     * @return the ioctlFlags
     */
    public int getIoctlFlags() {
        return this.ioctlFlags;
    }

    /**
     * Gets the file identifier from the response.
     *
     * @return the fileId
     */
    public byte[] getFileId() {
        return this.fileId;
    }

    /**
     * Gets the decoded output data from the response.
     *
     * @return the outputData
     */
    public Decodable getOutputData() {
        return this.outputData;
    }

    /**
     * Gets the length of the output data.
     *
     * @return the outputLength
     */
    public int getOutputLength() {
        return this.outputLength;
    }

    /**
     * Gets the decoded input data from the response.
     *
     * @return the inputData
     */
    public Decodable getInputData() {
        return this.inputData;
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
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#isErrorResponseStatus()
     */
    @Override
    protected boolean isErrorResponseStatus() {
        final int status = getStatus();
        return status != NtStatus.NT_STATUS_INVALID_PARAMETER && ((status != NtStatus.NT_STATUS_INVALID_PARAMETER)
                || ((this.ctlCode != Smb2IoctlRequest.FSCTL_SRV_COPYCHUNK) && (this.ctlCode != Smb2IoctlRequest.FSCTL_SRV_COPYCHUNK_WRITE)))
                && ((status != NtStatus.NT_STATUS_BUFFER_OVERFLOW)
                        || ((this.ctlCode != Smb2IoctlRequest.FSCTL_PIPE_TRANSCEIVE) && (this.ctlCode != Smb2IoctlRequest.FSCTL_PIPE_PEEK)
                                && (this.ctlCode != Smb2IoctlRequest.FSCTL_DFS_GET_REFERRALS)))
                && super.isErrorResponseStatus();
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
            return super.readErrorResponse(buffer, bufferIndex);
        }
        if (structureSize != 49) {
            throw new SMBProtocolDecodingException("Expected structureSize = 49");
        }
        bufferIndex += 4;
        this.ctlCode = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        this.fileId = new byte[16];
        System.arraycopy(buffer, bufferIndex, this.fileId, 0, 16);
        bufferIndex += 16;

        final int inputOffset = SMBUtil.readInt4(buffer, bufferIndex) + getHeaderStart();
        bufferIndex += 4;

        final int inputCount = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        final int outputOffset = SMBUtil.readInt4(buffer, bufferIndex) + getHeaderStart();
        bufferIndex += 4;

        final int outputCount = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        this.ioctlFlags = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        bufferIndex += 4; // Reserved2

        this.inputData = createInputDecodable();
        this.outputData = this.outputBuffer == null ? createOutputDecodable() : null;

        if (this.inputData != null) {
            this.inputData.decode(buffer, inputOffset, inputCount);
        }
        bufferIndex = Math.max(inputOffset + inputCount, bufferIndex);

        if (this.outputBuffer != null) {
            if (outputCount > this.outputBuffer.length) {
                throw new SMBProtocolDecodingException("Output length exceeds buffer size");
            }
            System.arraycopy(buffer, outputOffset, this.outputBuffer, 0, outputCount);
        } else if (this.outputData != null) {
            this.outputData.decode(buffer, outputOffset, outputCount);
        }
        this.outputLength = outputCount;
        bufferIndex = Math.max(outputOffset + outputCount, bufferIndex);
        return bufferIndex - start;
    }

    /**
     * Creates a decodable object for the output data based on the control code.
     *
     * @return the appropriate decodable object for the control code, or null if not recognized
     */
    protected Decodable createOutputDecodable() {
        switch (this.ctlCode) {
        case Smb2IoctlRequest.FSCTL_DFS_GET_REFERRALS:
            return new DfsReferralResponseBuffer();
        case Smb2IoctlRequest.FSCTL_SRV_REQUEST_RESUME_KEY:
            return new SrvRequestResumeKeyResponse();
        case Smb2IoctlRequest.FSCTL_SRV_COPYCHUNK:
        case Smb2IoctlRequest.FSCTL_SRV_COPYCHUNK_WRITE:
            return new SrvCopyChunkCopyResponse();
        case Smb2IoctlRequest.FSCTL_VALIDATE_NEGOTIATE_INFO:
            return new ValidateNegotiateInfoResponse();
        case Smb2IoctlRequest.FSCTL_PIPE_PEEK:
            return new SrvPipePeekResponse();
        }
        return null;
    }

    /**
     * Creates a decodable object for the input data based on the control code.
     *
     * @return the appropriate decodable object for the control code, or null if not recognized
     */
    protected Decodable createInputDecodable() {
        return null;
    }

    /**
     * Gets the output data decoded as the specified response type.
     *
     * @param <T> the type of the decoded response data
     * @param responseType the class of the expected response type
     * @return decoded data
     * @throws SmbException if decoding fails or the response type is incompatible
     */
    @SuppressWarnings("unchecked")
    public <T extends Decodable> T getOutputData(final Class<T> responseType) throws SmbException {

        final Decodable out = getOutputData();

        if (out == null) {
            throw new SmbException("Failed to decode output data");
        }

        if (!responseType.isAssignableFrom(out.getClass())) {
            throw new SmbException("Incompatible response data " + out.getClass());
        }
        return (T) out;
    }

}
