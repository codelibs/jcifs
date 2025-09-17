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
package org.codelibs.jcifs.smb.internal.smb2.create;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.smb2.RequestWithFileId;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Request;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.codelibs.jcifs.smb.util.Hexdump;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SMB2 Close request message. This command is used to close a file or directory
 * that was previously opened.
 *
 * @author mbechler
 *
 */
public class Smb2CloseRequest extends ServerMessageBlock2Request<Smb2CloseResponse> implements RequestWithFileId {

    private static final Logger log = LoggerFactory.getLogger(Smb2CloseRequest.class);

    private byte[] fileId;
    private final String fileName;
    private int closeFlags;

    /**
     * Constructs a close request with file ID and name
     *
     * @param config
     *            The configuration to use
     * @param fileId
     *            The file ID to close
     * @param fileName
     *            The name of the file being closed
     */
    public Smb2CloseRequest(final Configuration config, final byte[] fileId, final String fileName) {
        super(config, SMB2_CLOSE);
        this.fileId = fileId;
        this.fileName = fileName;
    }

    /**
     * Constructs a close request with file ID only
     *
     * @param config
     *            The configuration to use
     * @param fileId
     *            The file ID to close
     */
    public Smb2CloseRequest(final Configuration config, final byte[] fileId) {
        this(config, fileId, "");
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
     * Constructs a close request with file name only
     *
     * @param config
     *            The configuration to use
     * @param fileName
     *            The name of the file to close
     */
    public Smb2CloseRequest(final Configuration config, final String fileName) {
        this(config, Smb2Constants.UNSPECIFIED_FILEID, fileName);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Request#createResponse(org.codelibs.jcifs.smb.CIFSContext,
     *      org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Request)
     */
    @Override
    protected Smb2CloseResponse createResponse(final CIFSContext tc, final ServerMessageBlock2Request<Smb2CloseResponse> req) {
        return new Smb2CloseResponse(tc.getConfig(), this.fileId, this.fileName);
    }

    /**
     * Set the close flags
     *
     * @param flags
     *            the flags to set
     */
    public void setCloseFlags(final int flags) {
        this.closeFlags = flags;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest#size()
     */
    @Override
    public int size() {
        return size8(Smb2Constants.SMB2_HEADER_LENGTH + 24);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        SMBUtil.writeInt2(24, dst, dstIndex);
        SMBUtil.writeInt2(this.closeFlags, dst, dstIndex + 2);
        dstIndex += 4;
        dstIndex += 4; // Reserved
        System.arraycopy(this.fileId, 0, dst, dstIndex, 16);
        dstIndex += 16;

        if (log.isDebugEnabled()) {
            log.debug(String.format("Closing %s (%s)", Hexdump.toHexString(this.fileId), this.fileName));
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
