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
package jcifs.internal.fscc;

import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;

/**
 * Represents the FILE_STANDARD_INFORMATION structure used in SMB2/3 file system control code (FSCC) operations.
 * This structure provides standard file information including allocation size, end-of-file position,
 * number of links, deletion status, and directory flag.
 */
public class FileStandardInfo implements BasicFileInformation {

    private long allocationSize;
    private long endOfFile;
    private int numberOfLinks;
    private boolean deletePending;
    private boolean directory;

    /**
     * Default constructor for decoding file standard information.
     */
    public FileStandardInfo() {
    }

    @Override
    public byte getFileInformationLevel() {
        return FILE_STANDARD_INFO;
    }

    @Override
    public int getAttributes() {
        return 0;
    }

    @Override
    public long getCreateTime() {
        return 0L;
    }

    @Override
    public long getLastWriteTime() {
        return 0L;
    }

    @Override
    public long getLastAccessTime() {
        return 0L;
    }

    @Override
    public long getSize() {
        return this.endOfFile;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Decodable#decode(byte[], int, int)
     */
    @Override
    public int decode(final byte[] buffer, int bufferIndex, final int len) throws SMBProtocolDecodingException {
        final int start = bufferIndex;
        this.allocationSize = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        this.endOfFile = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        this.numberOfLinks = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.deletePending = (buffer[bufferIndex] & 0xFF) > 0;
        bufferIndex++;
        this.directory = (buffer[bufferIndex++] & 0xFF) > 0;
        return bufferIndex - start;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#size()
     */
    @Override
    public int size() {
        return 22;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#encode(byte[], int)
     */
    @Override
    public int encode(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        SMBUtil.writeInt8(this.allocationSize, dst, dstIndex);
        dstIndex += 8;
        SMBUtil.writeInt8(this.endOfFile, dst, dstIndex);
        dstIndex += 8;
        SMBUtil.writeInt4(this.numberOfLinks, dst, dstIndex);
        dstIndex += 4;
        dst[dstIndex] = (byte) (this.deletePending ? 1 : 0);
        dstIndex++;
        dst[dstIndex++] = (byte) (this.directory ? 1 : 0);
        return dstIndex - start;
    }

    @Override
    public String toString() {
        return ("SmbQueryInfoStandard[" + "allocationSize=" + this.allocationSize + ",endOfFile=" + this.endOfFile + ",numberOfLinks="
                + this.numberOfLinks + ",deletePending=" + this.deletePending + ",directory=" + this.directory + "]");
    }
}