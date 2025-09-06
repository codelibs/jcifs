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
 * Represents the FILE_FS_SIZE_INFORMATION structure used to query file system size information.
 * This structure provides details about the total allocation units, free allocation units,
 * sectors per allocation unit, and bytes per sector for a file system volume.
 */
public class FileFsSizeInformation implements AllocInfo {

    private long alloc; // Also handles SmbQueryFSSizeInfo
    private long free;
    private int sectPerAlloc;
    private int bytesPerSect;

    /**
     * Default constructor for decoding file system size information.
     */
    public FileFsSizeInformation() {
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.fscc.FileSystemInformation#getFileSystemInformationClass()
     */
    @Override
    public byte getFileSystemInformationClass() {
        return FS_SIZE_INFO;
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
        this.alloc = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;

        this.free = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;

        this.sectPerAlloc = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        this.bytesPerSect = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        return bufferIndex - start;
    }

    @Override
    public String toString() {
        return ("SmbInfoAllocation[" + "alloc=" + this.alloc + ",free=" + this.free + ",sectPerAlloc=" + this.sectPerAlloc
                + ",bytesPerSect=" + this.bytesPerSect + "]");
    }

}