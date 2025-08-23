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
package jcifs.internal.smb2.create;

import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.smb2.lease.Smb2LeaseKey;
import jcifs.internal.util.SMBUtil;

/**
 * SMB2 Lease V2 Create Context Response
 *
 * MS-SMB2 2.2.14.2.11
 */
public class LeaseV2CreateContextResponse implements CreateContextResponse {

    /**
     * Context name for lease V2 response
     */
    public static final String CONTEXT_NAME = "RqL2";

    private static final byte[] CONTEXT_NAME_BYTES = CONTEXT_NAME.getBytes();

    private Smb2LeaseKey leaseKey;
    private int leaseState;
    private int leaseFlags;
    private Smb2LeaseKey parentLeaseKey;
    private int epoch;

    /**
     * Create a new lease V2 context response
     */
    public LeaseV2CreateContextResponse() {
    }

    @Override
    public byte[] getName() {
        return CONTEXT_NAME_BYTES;
    }

    /**
     * Gets the lease key from the V2 server response
     * @return the lease key
     */
    public Smb2LeaseKey getLeaseKey() {
        return leaseKey;
    }

    /**
     * Gets the lease state granted by the server for V2
     * @return the granted lease state
     */
    public int getLeaseState() {
        return leaseState;
    }

    /**
     * Gets the lease flags from the V2 server response
     * @return the lease flags
     */
    public int getLeaseFlags() {
        return leaseFlags;
    }

    /**
     * Gets the parent lease key from the V2 response
     * @return the parent lease key
     */
    public Smb2LeaseKey getParentLeaseKey() {
        return parentLeaseKey;
    }

    /**
     * Gets the lease epoch from the V2 response
     * @return the epoch
     */
    public int getEpoch() {
        return epoch;
    }

    @Override
    public int decode(byte[] buffer, int bufferIndex, int len) throws SMBProtocolDecodingException {
        int start = bufferIndex;

        if (len < 52) {
            throw new SMBProtocolDecodingException("Lease V2 context data too short: " + len);
        }

        // Read lease V2 data (52 bytes)
        byte[] keyBytes = new byte[16];
        System.arraycopy(buffer, bufferIndex, keyBytes, 0, 16);
        this.leaseKey = new Smb2LeaseKey(keyBytes);
        bufferIndex += 16;

        this.leaseState = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        this.leaseFlags = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        // LeaseDuration (8 bytes) - reserved, skip
        bufferIndex += 8;

        byte[] parentKeyBytes = new byte[16];
        System.arraycopy(buffer, bufferIndex, parentKeyBytes, 0, 16);
        this.parentLeaseKey = new Smb2LeaseKey(parentKeyBytes);
        bufferIndex += 16;

        this.epoch = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;

        // Reserved (2 bytes) - skip
        bufferIndex += 2;

        return bufferIndex - start;
    }
}
