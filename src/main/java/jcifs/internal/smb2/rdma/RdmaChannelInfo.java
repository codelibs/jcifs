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
package jcifs.internal.smb2.rdma;

public class RdmaChannelInfo {

    private final Smb2RdmaTransform transform;

    /**
     * Create new RDMA channel info
     *
     * @param remoteKey remote memory key for RDMA access (token)
     * @param address remote memory address (offset)
     * @param length length of the memory region
     */
    public RdmaChannelInfo(int remoteKey, long address, int length) {
        // Create SMB2_RDMA_TRANSFORM structure
        this.transform = new Smb2RdmaTransform(address, remoteKey, length);
    }

    /**
     * Create from SMB2 RDMA Transform
     *
     * @param transform the RDMA transform structure
     */
    public RdmaChannelInfo(Smb2RdmaTransform transform) {
        this.transform = transform;
    }

    /**
     * Get remote memory key
     *
     * @return remote memory key (token)
     */
    public int getRemoteKey() {
        return transform.getToken();
    }

    /**
     * Get remote memory address
     *
     * @return remote memory address (offset)
     */
    public long getAddress() {
        return transform.getOffset();
    }

    /**
     * Get length of memory region
     *
     * @return length in bytes
     */
    public int getLength() {
        return transform.getLength();
    }

    /**
     * Get the underlying RDMA transform structure
     *
     * @return RDMA transform
     */
    public Smb2RdmaTransform getTransform() {
        return transform;
    }

    /**
     * Encode to byte array for SMB2 READ/WRITE channel info
     *
     * @param dst destination buffer
     * @param dstIndex starting index
     * @return number of bytes written
     */
    public int encode(byte[] dst, int dstIndex) {
        return transform.encode(dst, dstIndex);
    }

    @Override
    public String toString() {
        return String.format("RdmaChannelInfo[key=0x%x, addr=0x%x, len=%d]", getRemoteKey(), getAddress(), getLength());
    }
}
