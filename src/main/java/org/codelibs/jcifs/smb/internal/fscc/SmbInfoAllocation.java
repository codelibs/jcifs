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
package org.codelibs.jcifs.smb.internal.fscc;

import org.codelibs.jcifs.smb.internal.AllocInfo;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * Represents the SMB_INFO_ALLOCATION information level used in SMB transaction requests.
 * This structure provides allocation information for a file system including total units,
 * free units, sectors per allocation unit, and bytes per sector.
 */
public class SmbInfoAllocation implements AllocInfo {

    /**
     * Default constructor for SMB allocation information.
     */
    public SmbInfoAllocation() {
        // Default constructor
    }

    private long alloc; // Also handles SmbQueryFSSizeInfo
    private long free;
    private int sectPerAlloc;
    private int bytesPerSect;

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.fscc.FileSystemInformation#getFileSystemInformationClass()
     */
    @Override
    public byte getFileSystemInformationClass() {
        return FileSystemInformation.SMB_INFO_ALLOCATION;
    }

    @Override
    public long getCapacity() {
        return this.alloc * this.sectPerAlloc * this.bytesPerSect;
    }

    @Override
    public long getFree() {
        return this.free * this.sectPerAlloc * this.bytesPerSect;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Decodable#decode(byte[], int, int)
     */
    @Override
    public int decode(final byte[] buffer, int bufferIndex, final int len) throws SMBProtocolDecodingException {
        final int start = bufferIndex;
        bufferIndex += 4; // skip idFileSystem

        this.sectPerAlloc = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        this.alloc = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        this.free = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        this.bytesPerSect = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 4;

        return bufferIndex - start;
    }

    @Override
    public String toString() {
        return ("SmbInfoAllocation[" + "alloc=" + this.alloc + ",free=" + this.free + ",sectPerAlloc=" + this.sectPerAlloc
                + ",bytesPerSect=" + this.bytesPerSect + "]");
    }

}