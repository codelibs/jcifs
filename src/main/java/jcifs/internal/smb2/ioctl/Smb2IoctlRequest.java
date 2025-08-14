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

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.Encodable;
import jcifs.internal.smb2.RequestWithFileId;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;

/**
 * @author mbechler
 *
 */
public class Smb2IoctlRequest extends ServerMessageBlock2Request<Smb2IoctlResponse> implements RequestWithFileId {

    /**
     *
     */
    public static final int FSCTL_DFS_GET_REFERRALS = 0x0060194;
    /**
     *
     */
    public static final int FSCTL_PIPE_PEEK = 0x0011400C;
    /**
     *
     */
    public static final int FSCTL_PIPE_WAIT = 0x00110018;
    /**
     *
     */
    public static final int FSCTL_PIPE_TRANSCEIVE = 0x0011C017;
    /**
     *
     */
    public static final int FSCTL_SRV_COPYCHUNK = 0x001440F2;
    /**
     *
     */
    public static final int FSCTL_SRV_ENUMERATE_SNAPSHOTS = 0x00144064;
    /**
     *
     */
    public static final int FSCTL_SRV_REQUEST_RESUME_KEY = 0x00140078;
    /**
     *
     */
    public static final int FSCTL_SRV_READ_HASH = 0x001441bb;
    /**
     *
     */
    public static final int FSCTL_SRV_COPYCHUNK_WRITE = 0x001480F2;
    /**
     *
     */
    public static final int FSCTL_LRM_REQUEST_RESILENCY = 0x001401D4;
    /**
     *
     */
    public static final int FSCTL_QUERY_NETWORK_INTERFACE_INFO = 0x001401FC;
    /**
     *
     */
    public static final int FSCTL_SET_REPARSE_POINT = 0x000900A4;
    /**
     *
     */
    public static final int FSCTL_DFS_GET_REFERRALS_EX = 0x000601B0;
    /**
     *
     */
    public static final int FSCTL_FILE_LEVEL_TRIM = 0x00098208;
    /**
     *
     */
    public static final int FSCTL_VALIDATE_NEGOTIATE_INFO = 0x000140204;

    /**
     *
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
     * @param config
     * @param controlCode
     *
     */
    public Smb2IoctlRequest(final Configuration config, final int controlCode) {
        this(config, controlCode, Smb2Constants.UNSPECIFIED_FILEID);
    }

    /**
     * @param config
     * @param controlCode
     * @param fileId
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
     * @see jcifs.internal.smb2.RequestWithFileId#setFileId(byte[])
     */
    @Override
    public void setFileId(final byte[] fileId) {
        this.fileId = fileId;
    }

    /**
     *
     * @param config
     * @param controlCode
     * @param fileId
     * @param outputBuffer
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
     * @param flags
     *            the flags to set
     */
    public void setFlags(final int flags) {
        this.flags = flags;
    }

    /**
     * @param maxInputResponse
     *            the maxInputResponse to set
     */
    public void setMaxInputResponse(final int maxInputResponse) {
        this.maxInputResponse = maxInputResponse;
    }

    /**
     * @param maxOutputResponse
     *            the maxOutputResponse to set
     */
    public void setMaxOutputResponse(final int maxOutputResponse) {
        this.maxOutputResponse = maxOutputResponse;
    }

    /**
     * @param inputData
     *            the inputData to set
     */
    public void setInputData(final Encodable inputData) {
        this.inputData = inputData;
    }

    /**
     * @param outputData
     *            the outputData to set
     */
    public void setOutputData(final Encodable outputData) {
        this.outputData = outputData;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#size()
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
     * @see jcifs.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
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
     * @see jcifs.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat(final byte[] buffer, final int bufferIndex) {
        return 0;
    }

}
