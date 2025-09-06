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
package org.codelibs.jcifs.smb.internal.smb2.nego;

import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2 RDMA Transform Capabilities negotiate context.
 *
 * This context is used during SMB2 negotiation to indicate RDMA transform
 * capabilities when SMB Direct is supported by the client and server.
 */
public class Smb2RdmaTransformCapabilitiesContext implements NegotiateContextRequest, NegotiateContextResponse {

    // Context type
    /** Context ID for RDMA transform capabilities */
    public static final int CONTEXT_ID = Smb2Constants.SMB2_RDMA_TRANSFORM_CAPABILITIES;

    // Transform count and reserved fields
    private int transformCount = 1; // Number of transforms (always 1 for SMBDirect)
    private int reserved1 = 0;
    private int reserved2 = 0;

    // SMB_DIRECT_RDMA_TRANSFORM_V1
    private int rdmaTransformId = 0x0001; // SMB_DIRECT_RDMA_TRANSFORM_V1

    /**
     * Create RDMA Transform Capabilities context
     */
    public Smb2RdmaTransformCapabilitiesContext() {
    }

    @Override
    public int getContextType() {
        return CONTEXT_ID;
    }

    /**
     * Get the context data
     *
     * @return encoded context data
     */
    public byte[] getData() {
        // Encode the context data
        byte[] data = new byte[20]; // 2 + 2 + 4 + 4 + 4 + 4

        int idx = 0;
        SMBUtil.writeInt2(transformCount, data, idx);
        idx += 2;
        SMBUtil.writeInt2(reserved1, data, idx);
        idx += 2;
        SMBUtil.writeInt4(reserved2, data, idx);
        idx += 4;

        // SMB_DIRECT_RDMA_TRANSFORM array (only one element)
        SMBUtil.writeInt2(rdmaTransformId, data, idx);
        idx += 2;
        SMBUtil.writeInt2(0, data, idx); // Reserved
        idx += 2;
        SMBUtil.writeInt4(0, data, idx); // Reserved
        idx += 4;

        return data;
    }

    @Override
    public int encode(byte[] dst, int dstIndex) {
        byte[] data = getData();
        System.arraycopy(data, 0, dst, dstIndex, data.length);
        return data.length;
    }

    @Override
    public int decode(byte[] buffer, int bufferIndex, int len) throws SMBProtocolDecodingException {
        if (len < 20) {
            throw new SMBProtocolDecodingException("Invalid RDMA Transform Capabilities context length: " + len);
        }

        int start = bufferIndex;

        transformCount = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        reserved1 = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        reserved2 = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        // Read the transform (only expecting one)
        if (transformCount > 0) {
            rdmaTransformId = SMBUtil.readInt2(buffer, bufferIndex);
            bufferIndex += 2;
            // Skip reserved fields at bufferIndex + 2 and bufferIndex + 4
            bufferIndex += 6; // 2 + 4 for reserved fields
        }

        return bufferIndex - start;
    }

    @Override
    public int size() {
        return 20; // Fixed size: 2 + 2 + 4 + 12 (transform structure)
    }

    /**
     * Check if RDMA is supported based on this context
     *
     * @return true if RDMA Transform V1 is supported
     */
    public boolean isRdmaSupported() {
        return transformCount > 0 && rdmaTransformId == 0x0001;
    }

    /**
     * Get the transform count
     *
     * @return number of transforms
     */
    public int getTransformCount() {
        return transformCount;
    }

    /**
     * Get the RDMA transform ID
     *
     * @return transform ID (should be 0x0001 for V1)
     */
    public int getRdmaTransformId() {
        return rdmaTransformId;
    }
}