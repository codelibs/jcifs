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
package jcifs.internal.smb2.lock;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.smb2.RequestWithFileId;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;

/**
 * SMB2 Lock request message. This command is used to request byte-range locks
 * on portions of a file.
 *
 * @author mbechler
 *
 */
public class Smb2LockRequest extends ServerMessageBlock2Request<Smb2LockResponse> implements RequestWithFileId {

    private int lockSequenceNumber;
    private int lockSequenceIndex;
    private byte[] fileId;
    private final Smb2Lock[] locks;

    /**
     * Constructs an SMB2 lock request with the specified parameters.
     *
     * @param config the configuration for this request
     * @param fileId the file identifier for the file to lock
     * @param locks the array of lock elements to apply
     */
    public Smb2LockRequest(final Configuration config, final byte[] fileId, final Smb2Lock[] locks) {
        super(config, SMB2_LOCK);
        this.fileId = fileId;
        this.locks = locks;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2Request#createResponse(jcifs.CIFSContext,
     *      jcifs.internal.smb2.ServerMessageBlock2Request)
     */
    @Override
    protected Smb2LockResponse createResponse(final CIFSContext tc, final ServerMessageBlock2Request<Smb2LockResponse> req) {
        return new Smb2LockResponse(tc.getConfig());
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
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#size()
     */
    @Override
    public int size() {
        int size = Smb2Constants.SMB2_HEADER_LENGTH + 24;
        for (final Smb2Lock l : this.locks) {
            size += l.size();
        }
        return size8(size);
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        SMBUtil.writeInt2(48, dst, dstIndex);
        SMBUtil.writeInt2(this.locks.length, dst, dstIndex + 2);
        dstIndex += 4;
        SMBUtil.writeInt4((this.lockSequenceNumber & 0xF) << 28 | this.lockSequenceIndex & 0x0FFFFFFF, dst, dstIndex);
        dstIndex += 4;
        System.arraycopy(this.fileId, 0, dst, dstIndex, 16);
        dstIndex += 16;

        for (final Smb2Lock l : this.locks) {
            dstIndex += l.encode(dst, dstIndex);
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
