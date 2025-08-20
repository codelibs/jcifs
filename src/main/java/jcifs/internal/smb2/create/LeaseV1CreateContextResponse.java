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
package jcifs.internal.smb2.create;

import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.smb2.lease.Smb2LeaseKey;
import jcifs.internal.util.SMBUtil;

/**
 * SMB2 Lease V1 Create Context Response
 *
 * MS-SMB2 2.2.14.2.10
 */
public class LeaseV1CreateContextResponse implements CreateContextResponse {

    /**
     * Context name for lease response
     */
    public static final String CONTEXT_NAME = "RqLs";

    private static final byte[] CONTEXT_NAME_BYTES = CONTEXT_NAME.getBytes();

    private Smb2LeaseKey leaseKey;
    private int leaseState;
    private int leaseFlags;

    /**
     * Create a new lease V1 context response
     */
    public LeaseV1CreateContextResponse() {
    }

    @Override
    public byte[] getName() {
        return CONTEXT_NAME_BYTES;
    }

    /**
     * @return the lease key
     */
    public Smb2LeaseKey getLeaseKey() {
        return leaseKey;
    }

    /**
     * @return the granted lease state
     */
    public int getLeaseState() {
        return leaseState;
    }

    /**
     * @return the lease flags
     */
    public int getLeaseFlags() {
        return leaseFlags;
    }

    @Override
    public int decode(byte[] buffer, int bufferIndex, int len) throws SMBProtocolDecodingException {
        int start = bufferIndex;

        if (len < 32) {
            throw new SMBProtocolDecodingException("Lease V1 context data too short: " + len);
        }

        // Read lease V1 data (32 bytes)
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

        return bufferIndex - start;
    }
}