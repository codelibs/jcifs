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

import java.util.Date;

import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;

/**
 * Represents the FILE_BASIC_INFORMATION structure used in SMB2/3 file system control code (FSCC) operations.
 * This structure contains basic file information including creation time, last access time, last write time,
 * change time, and file attributes for querying and setting file metadata.
 */
public class FileBasicInfo implements BasicFileInformation {

    private long createTime;
    private long lastAccessTime;
    private long lastWriteTime;
    private long changeTime;
    private int attributes;

    /**
     * Default constructor for decoding.
     */
    public FileBasicInfo() {
    }

    /**
     * Constructs file basic information.
     *
     * @param create file creation time
     * @param lastAccess last access time
     * @param lastWrite last write time
     * @param change last change time
     * @param attributes file attributes
     */
    public FileBasicInfo(final long create, final long lastAccess, final long lastWrite, final long change, final int attributes) {
        this.createTime = create;
        this.lastAccessTime = lastAccess;
        this.lastWriteTime = lastWrite;
        this.changeTime = change;
        this.attributes = attributes;

    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.fscc.FileInformation#getFileInformationLevel()
     */
    @Override
    public byte getFileInformationLevel() {
        return FileInformation.FILE_BASIC_INFO;
    }

    @Override
    public int getAttributes() {
        return this.attributes;
    }

    @Override
    public long getCreateTime() {
        return this.createTime;
    }

    @Override
    public long getLastWriteTime() {
        return this.lastWriteTime;
    }

    @Override
    public long getLastAccessTime() {
        return this.lastAccessTime;
    }

    @Override
    public long getSize() {
        return 0L;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Decodable#decode(byte[], int, int)
     */
    @Override
    public int decode(final byte[] buffer, int bufferIndex, final int len) throws SMBProtocolDecodingException {
        final int start = bufferIndex;
        this.createTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.lastAccessTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.lastWriteTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.changeTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.attributes = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        return bufferIndex - start;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#size()
     */
    @Override
    public int size() {
        return 40;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#encode(byte[], int)
     */
    @Override
    public int encode(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        SMBUtil.writeTime(this.createTime, dst, dstIndex);
        dstIndex += 8;
        SMBUtil.writeTime(this.lastAccessTime, dst, dstIndex);
        dstIndex += 8;
        SMBUtil.writeTime(this.lastWriteTime, dst, dstIndex);
        dstIndex += 8;
        SMBUtil.writeTime(this.changeTime, dst, dstIndex);
        dstIndex += 8;
        SMBUtil.writeInt4(this.attributes, dst, dstIndex);
        dstIndex += 4;
        dstIndex += 4;
        return dstIndex - start;
    }

    @Override
    public String toString() {
        return ("SmbQueryFileBasicInfo[" + "createTime=" + new Date(this.createTime) + ",lastAccessTime=" + new Date(this.lastAccessTime)
                + ",lastWriteTime=" + new Date(this.lastWriteTime) + ",changeTime=" + new Date(this.changeTime) + ",attributes=0x"
                + Hexdump.toHexString(this.attributes, 4) + "]");
    }
}