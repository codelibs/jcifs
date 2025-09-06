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
package org.codelibs.jcifs.smb.internal.smb2.rdma;

import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2 RDMA Transform structure for READ/WRITE channel info.
 *
 * As per MS-SMB2 2.2.13.1.1 and 2.2.21.1.1
 */
public class Smb2RdmaTransform {

    // SMB_DIRECT_BUFFER_DESCRIPTOR_V1 structure
    private long offset; // 8 bytes: Offset within registered buffer
    private int token; // 4 bytes: RDMA provider token
    private int length; // 4 bytes: Length of buffer

    /**
     * Create SMB2 RDMA Transform
     *
     * @param offset offset within registered buffer
     * @param token RDMA provider token (steering tag/memory handle)
     * @param length length of buffer
     */
    public Smb2RdmaTransform(long offset, int token, int length) {
        this.offset = offset;
        this.token = token;
        this.length = length;
    }

    /**
     * Get buffer offset
     *
     * @return offset within registered buffer
     */
    public long getOffset() {
        return offset;
    }

    /**
     * Get RDMA token
     *
     * @return RDMA provider token
     */
    public int getToken() {
        return token;
    }

    /**
     * Get buffer length
     *
     * @return buffer length
     */
    public int getLength() {
        return length;
    }

    /**
     * Get size of this structure
     *
     * @return size in bytes (16)
     */
    public static int size() {
        return 16; // 8 + 4 + 4
    }

    /**
     * Encode this structure to byte array
     *
     * @param dst destination buffer
     * @param dstIndex starting index
     * @return number of bytes written
     */
    public int encode(byte[] dst, int dstIndex) {
        SMBUtil.writeInt8(offset, dst, dstIndex);
        SMBUtil.writeInt4(token, dst, dstIndex + 8);
        SMBUtil.writeInt4(length, dst, dstIndex + 12);
        return 16;
    }

    /**
     * Decode from byte array
     *
     * @param buffer source buffer
     * @param bufferIndex starting index
     * @return decoded transform
     */
    public static Smb2RdmaTransform decode(byte[] buffer, int bufferIndex) {
        long offset = SMBUtil.readInt8(buffer, bufferIndex);
        int token = SMBUtil.readInt4(buffer, bufferIndex + 8);
        int length = SMBUtil.readInt4(buffer, bufferIndex + 12);
        return new Smb2RdmaTransform(offset, token, length);
    }
}