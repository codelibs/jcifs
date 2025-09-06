/*
 * © 2025 CodeLibs, Inc.
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
import org.codelibs.jcifs.smb.internal.smb2.lease.Smb2LeaseKey;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2 Lease Break Notification
 *
 * MS-SMB2 2.2.23
 */
public class Smb2LeaseBreakNotification extends ServerMessageBlock2Response {

    private int structureSize;
    private int flags;
    private Smb2LeaseKey leaseKey;
    private int currentLeaseState;
    private int newLeaseState;
    private int breakReason;
    private int accessMaskHint;
    private int shareAccessHint;

    /**
     * Constructs an SMB2 lease break notification with the given configuration.
     *
     * @param config the configuration for this notification
     */
    public Smb2LeaseBreakNotification(Configuration config) {
        super(config);
    }

    /**
     * Gets the lease key that is being broken
     * @return the lease key
     */
    public Smb2LeaseKey getLeaseKey() {
        return leaseKey;
    }

    /**
     * Gets the current lease state before the break
     * @return the current lease state
     */
    public int getCurrentLeaseState() {
        return currentLeaseState;
    }

    /**
     * Gets the new lease state after the break
     * @return the new lease state
     */
    public int getNewLeaseState() {
        return newLeaseState;
    }

    /**
     * Gets the reason for the lease break
     * @return the break reason
     */
    public int getBreakReason() {
        return breakReason;
    }

    /**
     * Gets the lease flags from the notification
     * @return the lease flags
     */
    public int getLeaseFlags() {
        return flags;
    }

    /**
     * Gets the access mask hint for optimizing lease handling
     * @return the access mask hint
     */
    public int getAccessMaskHint() {
        return accessMaskHint;
    }

    /**
     * Gets the share access hint for optimizing lease handling
     * @return the share access hint
     */
    public int getShareAccessHint() {
        return shareAccessHint;
    }

    @Override
    protected int writeBytesWireFormat(byte[] dst, int dstIndex) {
        // Lease break notifications are sent by the server, not written by client
        return 0;
    }

    @Override
    protected int readBytesWireFormat(byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException {
        int start = bufferIndex;

        // StructureSize (2 bytes) - must be 44
        this.structureSize = SMBUtil.readInt2(buffer, bufferIndex);
        if (this.structureSize != 44) {
            throw new SMBProtocolDecodingException("Invalid lease break structure size: " + this.structureSize);
        }
        bufferIndex += 2;

        // Reserved (2 bytes)
        bufferIndex += 2;

        // Flags (4 bytes)
        this.flags = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        // LeaseKey (16 bytes)
        byte[] keyBytes = new byte[16];
        System.arraycopy(buffer, bufferIndex, keyBytes, 0, 16);
        this.leaseKey = new Smb2LeaseKey(keyBytes);
        bufferIndex += 16;

        // CurrentLeaseState (4 bytes)
        this.currentLeaseState = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        // NewLeaseState (4 bytes)
        this.newLeaseState = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        // BreakReason (4 bytes)
        this.breakReason = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        // AccessMaskHint (4 bytes)
        this.accessMaskHint = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        // ShareAccessHint (4 bytes)
        this.shareAccessHint = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        return bufferIndex - start;
    }

    @Override
    public String toString() {
        return String.format("Smb2LeaseBreakNotification[leaseKey=%s,currentState=0x%x,newState=0x%x,reason=%d]", leaseKey,
                currentLeaseState, newLeaseState, breakReason);
    }
}
