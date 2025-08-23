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
package jcifs.internal.smb2.lock;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.smb2.lease.Smb2LeaseKey;
import jcifs.internal.util.SMBUtil;

/**
 * SMB2 Lease Break Acknowledgment
 *
 * MS-SMB2 2.2.24
 */
public class Smb2LeaseBreakAcknowledgment extends ServerMessageBlock2Request<Smb2LeaseBreakResponse> {

    private static final int STRUCTURE_SIZE = 36;

    private int flags;
    private Smb2LeaseKey leaseKey;
    private int leaseState;

    /**
     * Create a lease break acknowledgment
     *
     * @param config configuration
     * @param leaseKey lease key
     * @param leaseState acknowledged lease state
     */
    public Smb2LeaseBreakAcknowledgment(Configuration config, Smb2LeaseKey leaseKey, int leaseState) {
        super(config, SMB2_OPLOCK_BREAK);
        this.leaseKey = leaseKey;
        this.leaseState = leaseState;
        this.flags = 0;
    }

    /**
     * Create a lease break acknowledgment
     *
     * @param context CIFS context
     * @param leaseKey lease key
     * @param leaseState acknowledged lease state
     */
    public Smb2LeaseBreakAcknowledgment(CIFSContext context, Smb2LeaseKey leaseKey, int leaseState) {
        this(context.getConfig(), leaseKey, leaseState);
    }

    /**
     * Gets the lease key for this acknowledgment
     * @return the lease key
     */
    public Smb2LeaseKey getLeaseKey() {
        return leaseKey;
    }

    /**
     * Gets the lease state being acknowledged
     * @return the lease state
     */
    public int getLeaseState() {
        return leaseState;
    }

    /**
     * Gets the lease flags for this acknowledgment
     * @return the lease flags
     */
    public int getLeaseFlags() {
        return flags;
    }

    /**
     * Sets the lease flags for this acknowledgment
     * @param flags the lease flags to set
     */
    public void setLeaseFlags(int flags) {
        this.flags = flags;
    }

    @Override
    protected Smb2LeaseBreakResponse createResponse(CIFSContext tc, ServerMessageBlock2Request<Smb2LeaseBreakResponse> req) {
        return new Smb2LeaseBreakResponse(tc.getConfig());
    }

    @Override
    public int size() {
        return size8(Smb2Constants.SMB2_HEADER_LENGTH + STRUCTURE_SIZE);
    }

    @Override
    protected int writeBytesWireFormat(byte[] dst, int dstIndex) {
        int start = dstIndex;

        // StructureSize (2 bytes) - must be 36
        SMBUtil.writeInt2(STRUCTURE_SIZE, dst, dstIndex);
        dstIndex += 2;

        // Reserved (2 bytes)
        SMBUtil.writeInt2(0, dst, dstIndex);
        dstIndex += 2;

        // Flags (4 bytes)
        SMBUtil.writeInt4(flags, dst, dstIndex);
        dstIndex += 4;

        // LeaseKey (16 bytes)
        leaseKey.encode(dst, dstIndex);
        dstIndex += 16;

        // LeaseState (4 bytes)
        SMBUtil.writeInt4(leaseState, dst, dstIndex);
        dstIndex += 4;

        // LeaseDuration (8 bytes) - must be zero for acknowledgment
        SMBUtil.writeInt8(0, dst, dstIndex);
        dstIndex += 8;

        return dstIndex - start;
    }

    @Override
    protected int readBytesWireFormat(byte[] buffer, int bufferIndex) {
        // This is a request, not a response, so this method is not used
        return 0;
    }

    @Override
    public String toString() {
        return String.format("Smb2LeaseBreakAcknowledgment[leaseKey=%s,leaseState=0x%x,flags=0x%x]", leaseKey, leaseState, flags);
    }
}
