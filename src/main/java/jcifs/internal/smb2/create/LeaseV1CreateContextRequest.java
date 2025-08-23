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

import jcifs.internal.smb2.lease.Smb2LeaseKey;
import jcifs.internal.util.SMBUtil;

/**
 * SMB2 Lease V1 Create Context Request
 *
 * MS-SMB2 2.2.13.2.8
 */
public class LeaseV1CreateContextRequest implements CreateContextRequest {

    /**
     * Context name for lease request
     */
    public static final String CONTEXT_NAME = "RqLs";

    private static final byte[] CONTEXT_NAME_BYTES = CONTEXT_NAME.getBytes();

    private Smb2LeaseKey leaseKey;
    private int leaseState;
    private int leaseFlags;

    /**
     * Create a new lease V1 context request
     */
    public LeaseV1CreateContextRequest() {
        this.leaseKey = new Smb2LeaseKey();
        this.leaseState = 0;
        this.leaseFlags = 0;
    }

    /**
     * Create a new lease V1 context request with specified parameters
     *
     * @param leaseKey the lease key
     * @param leaseState requested lease state
     */
    public LeaseV1CreateContextRequest(Smb2LeaseKey leaseKey, int leaseState) {
        this.leaseKey = leaseKey;
        this.leaseState = leaseState;
        this.leaseFlags = 0;
    }

    @Override
    public byte[] getName() {
        return CONTEXT_NAME_BYTES;
    }

    /**
     * Gets the lease key for this lease request
     * @return the lease key
     */
    public Smb2LeaseKey getLeaseKey() {
        return leaseKey;
    }

    /**
     * Sets the lease key for this lease request
     * @param leaseKey the lease key to set
     */
    public void setLeaseKey(Smb2LeaseKey leaseKey) {
        this.leaseKey = leaseKey;
    }

    /**
     * Gets the requested lease state flags
     * @return the requested lease state
     */
    public int getLeaseState() {
        return leaseState;
    }

    /**
     * Sets the requested lease state flags
     * @param leaseState the lease state to set
     */
    public void setLeaseState(int leaseState) {
        this.leaseState = leaseState;
    }

    /**
     * Gets the lease flags for this request
     * @return the lease flags
     */
    public int getLeaseFlags() {
        return leaseFlags;
    }

    /**
     * Sets the lease flags for this request
     * @param leaseFlags the lease flags to set
     */
    public void setLeaseFlags(int leaseFlags) {
        this.leaseFlags = leaseFlags;
    }

    @Override
    public int size() {
        // Context header: 16 bytes
        // Name: 4 bytes ("RqLs")
        // Padding: 4 bytes (to align data to 8-byte boundary)
        // Data: 32 bytes (lease V1 structure)
        return 16 + 4 + 4 + 32;
    }

    @Override
    public int encode(byte[] dst, int dstIndex) {
        int start = dstIndex;

        // Write context header
        SMBUtil.writeInt4(0, dst, dstIndex); // Next (offset to next context, 0 for last)
        dstIndex += 4;

        SMBUtil.writeInt2(16, dst, dstIndex); // NameOffset (from start of context)
        dstIndex += 2;

        SMBUtil.writeInt2(4, dst, dstIndex); // NameLength
        dstIndex += 2;

        SMBUtil.writeInt2(0, dst, dstIndex); // Reserved
        dstIndex += 2;

        SMBUtil.writeInt2(24, dst, dstIndex); // DataOffset (from start of context)
        dstIndex += 2;

        SMBUtil.writeInt4(32, dst, dstIndex); // DataLength
        dstIndex += 4;

        // Write context name
        System.arraycopy(CONTEXT_NAME_BYTES, 0, dst, dstIndex, 4);
        dstIndex += 4;

        // Padding to align data to 8-byte boundary
        dstIndex += 4;

        // Write lease V1 data (32 bytes total)
        leaseKey.encode(dst, dstIndex); // LeaseKey (16 bytes)
        dstIndex += 16;

        SMBUtil.writeInt4(leaseState, dst, dstIndex); // LeaseState (4 bytes)
        dstIndex += 4;

        SMBUtil.writeInt4(leaseFlags, dst, dstIndex); // LeaseFlags (4 bytes)
        dstIndex += 4;

        SMBUtil.writeInt8(0, dst, dstIndex); // LeaseDuration (8 bytes) - reserved, must be zero
        dstIndex += 8;

        return dstIndex - start;
    }
}
