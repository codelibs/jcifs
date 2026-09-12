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
package org.codelibs.jcifs.smb.internal.smb2.lock;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Response;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.codelibs.jcifs.smb.util.Hexdump;

/**
 * SMB2 Oplock Break notification message. This server-initiated message notifies the client
 * that an opportunistic lock must be broken due to conflicting access from another client.
 *
 * @author mbechler
 *
 */
public class Smb2OplockBreakNotification extends ServerMessageBlock2Response {

    /** Body size of an oplock break notification, MS-SMB2 2.2.23.1 */
    private static final int OPLOCK_BREAK_STRUCTURE_SIZE = 24;

    /** Body size of a lease break notification, MS-SMB2 2.2.23.2 */
    private static final int LEASE_BREAK_STRUCTURE_SIZE = 44;

    private byte oplockLevel;
    private byte[] fileId;

    private boolean leaseBreak;
    private int newEpoch;
    private int breakFlags;
    private byte[] leaseKey;
    private int currentLeaseState;
    private int newLeaseState;

    /**
     * Constructs an SMB2 oplock break notification with the given configuration.
     *
     * @param config the configuration for this notification
     */
    public Smb2OplockBreakNotification(final Configuration config) {
        super(config);
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
    protected int readBytesWireFormat(final byte[] buffer, final int bufferIndex) throws SMBProtocolDecodingException {
        final int structureSize = SMBUtil.readInt2(buffer, bufferIndex);
        if (structureSize == OPLOCK_BREAK_STRUCTURE_SIZE) {
            return readOplockBreak(buffer, bufferIndex);
        }
        if (structureSize == LEASE_BREAK_STRUCTURE_SIZE) {
            return readLeaseBreak(buffer, bufferIndex);
        }
        throw new SMBProtocolDecodingException("Expected structureSize = 24 or 44");
    }

    /**
     * Reads an oplock break notification body, MS-SMB2 2.2.23.1.
     */
    private int readOplockBreak(final byte[] buffer, final int bufferIndex) {
        this.leaseBreak = false;
        this.oplockLevel = buffer[bufferIndex + 2];
        // 1 byte Reserved, 4 bytes Reserved2
        this.fileId = new byte[16];
        System.arraycopy(buffer, bufferIndex + 8, this.fileId, 0, 16);
        return OPLOCK_BREAK_STRUCTURE_SIZE;
    }

    /**
     * Reads a lease break notification body, MS-SMB2 2.2.23.2.
     *
     * <p>
     * BreakReason, AccessMaskHint and ShareMaskHint are reserved and are not decoded.
     * </p>
     */
    private int readLeaseBreak(final byte[] buffer, final int bufferIndex) {
        this.leaseBreak = true;
        this.newEpoch = SMBUtil.readInt2(buffer, bufferIndex + 2);
        this.breakFlags = SMBUtil.readInt4(buffer, bufferIndex + 4);
        this.leaseKey = new byte[16];
        System.arraycopy(buffer, bufferIndex + 8, this.leaseKey, 0, 16);
        this.currentLeaseState = SMBUtil.readInt4(buffer, bufferIndex + 24);
        this.newLeaseState = SMBUtil.readInt4(buffer, bufferIndex + 28);
        return LEASE_BREAK_STRUCTURE_SIZE;
    }

    /**
     * Whether this is a lease break rather than an oplock break.
     *
     * <p>
     * Both arrive as SMB2_OPLOCK_BREAK and are told apart only by their structure size, MS-SMB2 3.2.5.19. The lease
     * accessors carry a value only when this returns {@code true}, and the oplock accessors only when it returns
     * {@code false}.
     * </p>
     *
     * @return true when a lease break was decoded
     */
    public boolean isLeaseBreak() {
        return this.leaseBreak;
    }

    /**
     * @return the oplock level the server is breaking to, one of the {@code SMB2_OPLOCK_LEVEL_*} values
     */
    public byte getOplockLevel() {
        return this.oplockLevel;
    }

    /**
     * @return the file id of the open whose oplock is being broken, 16 bytes, or null for a lease break
     */
    public byte[] getFileId() {
        return this.fileId;
    }

    /**
     * @return the key of the lease being broken, 16 bytes, or null for an oplock break
     */
    public byte[] getLeaseKey() {
        return this.leaseKey;
    }

    /**
     * @return the lease epoch after the break, zero before SMB 3.0
     */
    public int getNewEpoch() {
        return this.newEpoch;
    }

    /**
     * @return the lease break flags; bit 0 is SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED
     */
    public int getBreakFlags() {
        return this.breakFlags;
    }

    /**
     * @return the lease state held before the break
     */
    public int getCurrentLeaseState() {
        return this.currentLeaseState;
    }

    /**
     * @return the lease state the server is breaking to
     */
    public int getNewLeaseState() {
        return this.newLeaseState;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#toString()
     */
    @Override
    public String toString() {
        if (this.leaseBreak) {
            // A lease break carries a lease key and no file id, so it cannot be printed as though it had one - and
            // the break path logs the notification, so getting this wrong takes the whole path down with it.
            return "Smb2LeaseBreakNotification[leaseKey=" + Hexdump.toHexString(this.leaseKey) + ",currentLeaseState="
                    + this.currentLeaseState + ",newLeaseState=" + this.newLeaseState + ",flags=" + this.breakFlags + ",epoch="
                    + this.newEpoch + "]";
        }
        return "Smb2OpblockBreakNotification[oplockLevel=" + this.oplockLevel + ",fileId=" + Hexdump.toHexString(this.fileId) + "]";
    }
}
