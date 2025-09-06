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
 * SMB2 Lease Break Response
 *
 * MS-SMB2 2.2.25
 */
public class Smb2LeaseBreakResponse extends ServerMessageBlock2Response {

    private int structureSize;
    private int flags;
    private Smb2LeaseKey leaseKey;
    private int leaseState;
    private long leaseDuration;

    /**
     * Constructs an SMB2 lease break response with the given configuration.
     *
     * @param config the configuration for this response
     */
    public Smb2LeaseBreakResponse(Configuration config) {
        super(config);
    }

    /**
     * Gets the lease key from the break response
     * @return the lease key
     */
    public Smb2LeaseKey getLeaseKey() {
        return leaseKey;
    }

    /**
     * Gets the granted lease state from the break response
     * @return the lease state
     */
    public int getLeaseState() {
        return leaseState;
    }

    /**
     * Gets the lease flags from the break response
     * @return the lease flags
     */
    public int getLeaseFlags() {
        return flags;
    }

    /**
     * Gets the lease duration from the break response
     * @return the lease duration
     */
    public long getLeaseDuration() {
        return leaseDuration;
    }

    @Override
    protected int writeBytesWireFormat(byte[] dst, int dstIndex) {
        // This is a response, not a request, so this method is not used
        return 0;
    }

    @Override
    protected int readBytesWireFormat(byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException {
        int start = bufferIndex;

        // StructureSize (2 bytes) - must be 36
        this.structureSize = SMBUtil.readInt2(buffer, bufferIndex);
        if (this.structureSize != 36) {
            throw new SMBProtocolDecodingException("Invalid lease break response structure size: " + this.structureSize);
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

        // LeaseState (4 bytes)
        this.leaseState = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        // LeaseDuration (8 bytes)
        this.leaseDuration = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;

        return bufferIndex - start;
    }

    @Override
    public String toString() {
        return String.format("Smb2LeaseBreakResponse[leaseKey=%s,leaseState=0x%x,flags=0x%x,duration=%d]", leaseKey, leaseState, flags,
                leaseDuration);
    }
}
