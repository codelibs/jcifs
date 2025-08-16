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
package jcifs.internal.smb2.info;

import java.nio.charset.StandardCharsets;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.smb2.RequestWithFileId;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;

/**
 * SMB2 Query Directory request message. This command is used to enumerate the contents
 * of a directory on the server.
 *
 * @author mbechler
 *
 */
public class Smb2QueryDirectoryRequest extends ServerMessageBlock2Request<Smb2QueryDirectoryResponse> implements RequestWithFileId {

    /**
     * File information class for basic directory information.
     */
    public static final byte FILE_DIRECTORY_INFO = 0x1;

    /**
     * File information class for full directory information.
     */
    public static final byte FILE_FULL_DIRECTORY_INFO = 0x2;

    /**
     * File information class for both names directory information.
     */
    public static final byte FILE_BOTH_DIRECTORY_INFO = 0x03;

    /**
     * File information class for file names only.
     */
    public static final byte FILE_NAMES_INFO = 0x0C;

    /**
     * File information class for both names with file IDs.
     */
    public static final byte FILE_ID_BOTH_DIRECTORY_INFO = 0x24;

    /**
     * File information class for full directory information with file IDs.
     */
    public static final byte FILE_ID_FULL_DIRECTORY_INFO = 0x26;

    /**
     * Flag to restart the directory enumeration from the beginning.
     */
    public static final byte SMB2_RESTART_SCANS = 0x1;

    /**
     * Flag to return only a single directory entry.
     */
    public static final byte SMB2_RETURN_SINGLE_ENTRY = 0x2;

    /**
     * Flag indicating that the file index field contains a valid index.
     */
    public static final byte SMB2_INDEX_SPECIFIED = 0x4;

    /**
     * Flag to reopen the directory enumeration.
     */
    public static final byte SMB2_REOPEN = 0x10;

    private byte fileInformationClass = FILE_BOTH_DIRECTORY_INFO;
    private byte queryFlags;
    private int fileIndex;
    private byte[] fileId;
    private final int outputBufferLength;
    private String fileName;

    /**
     * Constructs an SMB2 query directory request with the given configuration.
     *
     * @param config the configuration for this request
     */
    public Smb2QueryDirectoryRequest(final Configuration config) {
        this(config, Smb2Constants.UNSPECIFIED_FILEID);
    }

    /**
     * Constructs a SMB2 query directory request with the specified configuration and file ID
     *
     * @param config
     *            the configuration to use for this request
     * @param fileId
     *            the file ID of the directory to query
     */
    public Smb2QueryDirectoryRequest(final Configuration config, final byte[] fileId) {
        super(config, SMB2_QUERY_DIRECTORY);
        this.outputBufferLength =
                Math.min(config.getMaximumBufferSize(), config.getListSize()) - Smb2QueryDirectoryResponse.OVERHEAD & ~0x7;
        this.fileId = fileId;
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
     * Sets the file information class for the directory query
     *
     * @param fileInformationClass
     *            the fileInformationClass to set
     */
    public void setFileInformationClass(final byte fileInformationClass) {
        this.fileInformationClass = fileInformationClass;
    }

    /**
     * Sets the query flags for the directory enumeration
     *
     * @param queryFlags
     *            the queryFlags to set
     */
    public void setQueryFlags(final byte queryFlags) {
        this.queryFlags = queryFlags;
    }

    /**
     * Sets the file index from which to start the directory enumeration
     *
     * @param fileIndex
     *            the fileIndex to set
     */
    public void setFileIndex(final int fileIndex) {
        this.fileIndex = fileIndex;
    }

    /**
     * Sets the file name pattern for filtering directory results
     *
     * @param fileName
     *            the fileName to set
     */
    public void setFileName(final String fileName) {
        this.fileName = fileName;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2Request#createResponse(jcifs.CIFSContext,
     *      jcifs.internal.smb2.ServerMessageBlock2Request)
     */
    @Override
    protected Smb2QueryDirectoryResponse createResponse(final CIFSContext tc,
            final ServerMessageBlock2Request<Smb2QueryDirectoryResponse> req) {
        return new Smb2QueryDirectoryResponse(tc.getConfig(), this.fileInformationClass);
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#size()
     */
    @Override
    public int size() {
        return size8(Smb2Constants.SMB2_HEADER_LENGTH + 32 + (this.fileName != null ? 2 * this.fileName.length() : 0));
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        SMBUtil.writeInt2(33, dst, dstIndex);
        dst[dstIndex + 2] = this.fileInformationClass;
        dst[dstIndex + 3] = this.queryFlags;
        dstIndex += 4;
        SMBUtil.writeInt4(this.fileIndex, dst, dstIndex);
        dstIndex += 4;
        System.arraycopy(this.fileId, 0, dst, dstIndex, 16);
        dstIndex += 16;

        final int fnOffsetOffset = dstIndex;
        final int fnLengthOffset = dstIndex + 2;
        dstIndex += 4;

        SMBUtil.writeInt4(this.outputBufferLength, dst, dstIndex);
        dstIndex += 4;

        if (this.fileName == null) {
            SMBUtil.writeInt2(0, dst, fnOffsetOffset);
            SMBUtil.writeInt2(0, dst, fnLengthOffset);
        } else {
            final byte[] fnBytes = this.fileName.getBytes(StandardCharsets.UTF_16LE);
            SMBUtil.writeInt2(dstIndex - getHeaderStart(), dst, fnOffsetOffset);
            SMBUtil.writeInt2(fnBytes.length, dst, fnLengthOffset);
            System.arraycopy(fnBytes, 0, dst, dstIndex, fnBytes.length);
            dstIndex += fnBytes.length;
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
