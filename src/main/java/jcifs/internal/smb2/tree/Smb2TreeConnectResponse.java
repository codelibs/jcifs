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
package jcifs.internal.smb2.tree;

import jcifs.Configuration;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.TreeConnectResponse;
import jcifs.internal.smb2.ServerMessageBlock2;
import jcifs.internal.smb2.ServerMessageBlock2Response;
import jcifs.internal.util.SMBUtil;

/**
 * SMB2 Tree Connect response message.
 *
 * This response contains information about the connected
 * tree, including share type and capabilities.
 *
 * @author mbechler
 */
public class Smb2TreeConnectResponse extends ServerMessageBlock2Response implements TreeConnectResponse {

    /**
     * Share type constant for disk shares (file shares).
     */
    public static final byte SMB2_SHARE_TYPE_DISK = 0x1;
    /**
     * Share type constant for named pipe shares (IPC).
     */
    public static final byte SMB2_SHARE_TYPE_PIPE = 0x2;
    /**
     * Share type constant for printer shares.
     */
    public static final byte SMB2_SHARE_TYPE_PRINT = 0x3;

    /**
     * Share flag indicating manual caching of documents.
     */
    public static final int SMB2_SHAREFLAG_MANUAL_CACHING = 0x0;
    /**
     * Share flag indicating automatic caching of documents.
     */
    public static final int SMB2_SHAREFLAG_AUTO_CACHING = 0x10;
    /**
     * Share flag indicating automatic caching of programs and documents.
     */
    public static final int SMB2_SHAREFLAG_VDO_CACHING = 0x20;
    /**
     * Share flag indicating the share is in a DFS namespace.
     */
    public static final int SMB2_SHAREFLAG_DFS = 0x1;
    /**
     * Share flag indicating the share is a DFS root.
     */
    public static final int SMB2_SHAREFLAG_DFS_ROOT = 0x2;
    /**
     * Share flag indicating that exclusive opens are restricted on this share.
     */
    public static final int SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS = 0x100;
    /**
     * Share flag indicating that shared delete is forced for this share.
     */
    public static final int SMB2_SHAREFLAG_FORCE_SHARED_DELETE = 0x200;
    /**
     * Share flag indicating that namespace caching is allowed on this share.
     */
    public static final int SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING = 0x400;
    /**
     * Share flag indicating that access-based directory enumeration is enabled.
     */
    public static final int SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM = 0x800;
    /**
    * Share flag indicating that level 2 oplocks are forced on this share.
    */
    public static final int SMB2_SHAREFLAG_FORCE_LEVEL2_OPLOCK = 0x1000;
    /**
     * Share flag indicating that hash generation V1 is enabled for this share.
     */
    public static final int SMB2_SHAREFLAG_ENABLE_HASH_V1 = 0x2000;
    /**
     * Share flag indicating that hash generation V2 is enabled for this share.
     */
    public static final int SMB2_SHAREFLAG_ENABLE_HASH_V2 = 0x4000;
    /**
     * Share flag indicating that encryption is required for this share.
     */
    public static final int SMB2_SHAREFLAG_ENCRYPT_DATA = 0x8000;
    /**
     * Share capability indicating DFS support.
     */
    public static final int SMB2_SHARE_CAP_DFS = 0x8;

    /**
     * Share capability indicating continuous availability support.
     */
    public static final int SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY = 0x10;

    /**
     * Share capability indicating scale-out support.
     */
    public static final int SMB2_SHARE_CAP_SCALEOUT = 0x20;

    /**
     * Share capability indicating cluster support.
     */
    public static final int SMB2_SHARE_CAP_CLUSTER = 0x40;

    /**
     * Share capability indicating asymmetric support.
     */
    public static final int SMB2_SHARE_CAP_ASYMMETRIC = 0x80;
    private byte shareType;
    private int shareFlags;
    private int capabilities;
    private int maximalAccess;

    /**
     * Creates a new SMB2 tree connect response.
     *
     * @param config the CIFS configuration
     */
    public Smb2TreeConnectResponse(final Configuration config) {
        super(config);
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2Response#prepare(jcifs.internal.CommonServerMessageBlockRequest)
     */
    @Override
    public void prepare(final CommonServerMessageBlockRequest next) {
        if (isReceived()) {
            ((ServerMessageBlock2) next).setTreeId(getTreeId());
        }
        super.prepare(next);
    }

    /**
     * Returns the type of the connected share (disk, pipe, or print).
     *
     * @return the shareType
     */
    public byte getShareType() {
        return this.shareType;
    }

    /**
     * Returns the flags describing characteristics of the connected share.
     *
     * @return the shareFlags
     */
    public int getShareFlags() {
        return this.shareFlags;
    }

    /**
     * Returns the capabilities of the connected share.
     *
     * @return the capabilities
     */
    public int getCapabilities() {
        return this.capabilities;
    }

    /**
     * Returns the maximal access rights that the user has on this share.
     *
     * @return the maximalAccess
     */
    public int getMaximalAccess() {
        return this.maximalAccess;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.TreeConnectResponse#getTid()
     */
    @Override
    public final int getTid() {
        return getTreeId();
    }

    @Override
    public boolean isValidTid() {
        return getTreeId() != -1;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.TreeConnectResponse#getService()
     */
    @Override
    public String getService() {
        return null;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.TreeConnectResponse#isShareDfs()
     */
    @Override
    public boolean isShareDfs() {
        return (this.shareFlags & (SMB2_SHAREFLAG_DFS | SMB2_SHAREFLAG_DFS_ROOT)) != 0
                || (this.capabilities & SMB2_SHARE_CAP_DFS) == SMB2_SHARE_CAP_DFS;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    /**
     * {@inheritDoc}
     *
     * @throws SMBProtocolDecodingException if an error occurs during decoding
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat(final byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException {
        final int start = bufferIndex;
        final int structureSize = SMBUtil.readInt2(buffer, bufferIndex);
        if (structureSize != 16) {
            throw new SMBProtocolDecodingException("Structure size is not 16");
        }

        this.shareType = buffer[bufferIndex + 2];
        bufferIndex += 4;
        this.shareFlags = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.capabilities = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.maximalAccess = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        return bufferIndex - start;
    }

}
