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

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.Encodable;
import org.codelibs.jcifs.smb.internal.smb2.RequestWithFileId;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Request;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2 IOCTL request message. This command is used to perform device control operations
 * on files, pipes, or the server itself.
 *
 * @author mbechler
 *
 */
public class Smb2IoctlRequest extends ServerMessageBlock2Request<Smb2IoctlResponse> implements RequestWithFileId {

    /**
     * Function code to retrieve DFS referrals
     */
    public static final int FSCTL_DFS_GET_REFERRALS = 0x0060194;
    /**
     * Function code to peek at named pipe data without removing it
     */
    public static final int FSCTL_PIPE_PEEK = 0x0011400C;
    /**
     * Function code to wait for a named pipe to become available
     */
    public static final int FSCTL_PIPE_WAIT = 0x00110018;
    /**
     * Function code to transceive data on a named pipe
     */
    public static final int FSCTL_PIPE_TRANSCEIVE = 0x0011C017;
    /**
     * Function code for server-side copy chunk operation
     */
    public static final int FSCTL_SRV_COPYCHUNK = 0x001440F2;
    /**
     * Function code to enumerate volume shadow copy snapshots
     */
    public static final int FSCTL_SRV_ENUMERATE_SNAPSHOTS = 0x00144064;
    /**
     * Function code to request a resume key for server-side copy
     */
    public static final int FSCTL_SRV_REQUEST_RESUME_KEY = 0x00140078;
    /**
     * Function code to read hash data from server
     */
    public static final int FSCTL_SRV_READ_HASH = 0x001441bb;
    /**
     * Function code for server-side copy chunk write operation
     */
    public static final int FSCTL_SRV_COPYCHUNK_WRITE = 0x001480F2;
    /**
     * Function code to request resilient handle for network failures
     */
    public static final int FSCTL_LRM_REQUEST_RESILENCY = 0x001401D4;
    /**
     * Function code to query network interface information
     */
    public static final int FSCTL_QUERY_NETWORK_INTERFACE_INFO = 0x001401FC;
    /**
     * Function code to set a reparse point on a file
     */
    public static final int FSCTL_SET_REPARSE_POINT = 0x000900A4;
    /**
     * Function code to retrieve extended DFS referrals
     */
    public static final int FSCTL_DFS_GET_REFERRALS_EX = 0x000601B0;
    /**
     * Function code to trim file level storage
     */
    public static final int FSCTL_FILE_LEVEL_TRIM = 0x00098208;
    /**
     * Function code to validate SMB2 negotiate information
     */
    public static final int FSCTL_VALIDATE_NEGOTIATE_INFO = 0x000140204;

    /**
     * Flag indicating this IOCTL is a file system control operation
     */
    public static final int SMB2_O_IOCTL_IS_FSCTL = 0x1;

    private byte[] fileId;
    private final int controlCode;
    private final byte[] outputBuffer;
    private int maxOutputResponse;
    private int maxInputResponse;
    private int flags;
    private Encodable inputData;
    private Encodable outputData;

    /**
     * Constructs an SMB2 IOCTL request with an unspecified file ID
     * @param config the client configuration
     * @param controlCode the IOCTL control code
     */
    public Smb2IoctlRequest(final Configuration config, final int controlCode) {
        this(config, controlCode, Smb2Constants.UNSPECIFIED_FILEID);
    }

    /**
     * Constructs an SMB2 IOCTL request with a specified file ID
     * @param config the client configuration
     * @param controlCode the IOCTL control code
     * @param fileId the file identifier
     */
    public Smb2IoctlRequest(final Configuration config, final int controlCode, final byte[] fileId) {
        super(config, SMB2_IOCTL);
        this.controlCode = controlCode;
        this.fileId = fileId;
        this.maxOutputResponse = config.getTransactionBufferSize() & ~0x7;
        this.outputBuffer = null;
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
     * Constructs an SMB2 IOCTL request with output buffer
     * @param config the client configuration
     * @param controlCode the IOCTL control code
     * @param fileId the file identifier
     * @param outputBuffer the output buffer for the IOCTL operation
     */
    public Smb2IoctlRequest(final Configuration config, final int controlCode, final byte[] fileId, final byte[] outputBuffer) {
        super(config, SMB2_IOCTL);
        this.controlCode = controlCode;
        this.fileId = fileId;
        this.outputBuffer = outputBuffer;
        this.maxOutputResponse = outputBuffer.length;
    }

    @Override
    protected Smb2IoctlResponse createResponse(final CIFSContext tc, final ServerMessageBlock2Request<Smb2IoctlResponse> req) {
        return new Smb2IoctlResponse(tc.getConfig(), this.outputBuffer, this.controlCode);
    }

    /**
     * Set the IOCTL flags
     * @param flags the flags to set
     */
    public void setFlags(final int flags) {
        this.flags = flags;
    }

    /**
     * Set the maximum input response size
     * @param maxInputResponse the maxInputResponse to set
     */
    public void setMaxInputResponse(final int maxInputResponse) {
        this.maxInputResponse = maxInputResponse;
    }

    /**
     * Set the maximum output response size
     * @param maxOutputResponse the maxOutputResponse to set
     */
    public void setMaxOutputResponse(final int maxOutputResponse) {
        this.maxOutputResponse = maxOutputResponse;
    }

    /**
     * Set the input data for the IOCTL request
     * @param inputData the inputData to set
     */
    public void setInputData(final Encodable inputData) {
        this.inputData = inputData;
    }

    /**
     * Set the output data for the IOCTL request
     * @param outputData the outputData to set
     */
    public void setOutputData(final Encodable outputData) {
        this.outputData = outputData;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest#size()
     */
    @Override
    public int size() {
        final int size = Smb2Constants.SMB2_HEADER_LENGTH + 56;
        int dataLength = 0;
        if (this.inputData != null) {
            dataLength += this.inputData.size();
        }
        if (this.outputData != null) {
            dataLength += this.outputData.size();
        }
        return size8(size + dataLength);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        SMBUtil.writeInt2(57, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.controlCode, dst, dstIndex);
        dstIndex += 4;
        System.arraycopy(this.fileId, 0, dst, dstIndex, 16);
        dstIndex += 16;

        final int inputOffsetOffset = dstIndex;
        dstIndex += 4;
        final int inputLengthOffset = dstIndex;
        dstIndex += 4;
        SMBUtil.writeInt4(this.maxInputResponse, dst, dstIndex);
        dstIndex += 4;

        final int outputOffsetOffset = dstIndex;
        dstIndex += 4;
        final int outputLengthOffset = dstIndex;
        dstIndex += 4;
        SMBUtil.writeInt4(this.maxOutputResponse, dst, dstIndex);
        dstIndex += 4;

        SMBUtil.writeInt4(this.flags, dst, dstIndex);
        dstIndex += 4;
        dstIndex += 4; // Reserved2

        if (this.inputData != null) {
            SMBUtil.writeInt4(dstIndex - getHeaderStart(), dst, inputOffsetOffset);
            final int len = this.inputData.encode(dst, dstIndex);
            SMBUtil.writeInt4(len, dst, inputLengthOffset);
            dstIndex += len;
        } else {
            SMBUtil.writeInt4(0, dst, inputOffsetOffset);
            SMBUtil.writeInt4(0, dst, inputLengthOffset);
        }

        if (this.outputData != null) {
            SMBUtil.writeInt4(dstIndex - getHeaderStart(), dst, outputOffsetOffset);
            final int len = this.outputData.encode(dst, dstIndex);
            SMBUtil.writeInt4(len, dst, outputLengthOffset);
            dstIndex += len;
        } else {
            SMBUtil.writeInt4(0, dst, outputOffsetOffset);
            SMBUtil.writeInt4(0, dst, outputLengthOffset);
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
