/* jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
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

package jcifs.internal.smb1.com;

import java.util.Date;

import jcifs.Configuration;
import jcifs.internal.SmbBasicFileInfo;
import jcifs.internal.smb1.AndXServerMessageBlock;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;

/**
 * SMB1 NT Create AndX Response message.
 *
 * This response contains information about the created or opened file,
 * including file handle, attributes, and creation disposition.
 */
public class SmbComNTCreateAndXResponse extends AndXServerMessageBlock implements SmbBasicFileInfo {

    static final int EXCLUSIVE_OPLOCK_GRANTED = 1;
    static final int BATCH_OPLOCK_GRANTED = 2;
    static final int LEVEL_II_OPLOCK_GRANTED = 3;

    private byte oplockLevel;
    private int fid, createAction, extFileAttributes, fileType, deviceState;
    private long creationTime, lastAccessTime, lastWriteTime, changeTime, allocationSize, endOfFile;
    private boolean directory;
    private boolean isExtended;

    /**
     * Constructs an NT Create AndX response.
     *
     * @param config the configuration
     */
    public SmbComNTCreateAndXResponse(final Configuration config) {
        super(config);
    }

    /**
     * Gets the file type.
     *
     * @return the fileType
     */
    public final int getFileType() {
        return this.fileType;
    }

    /**
     * Checks if the response is extended.
     *
     * @return the isExtended
     */
    public final boolean isExtended() {
        return this.isExtended;
    }

    /**
     * Sets whether the response is extended.
     *
     * @param isExtended
     *            the isExtended to set
     */
    public final void setExtended(final boolean isExtended) {
        this.isExtended = isExtended;
    }

    /**
     * Gets the oplock level granted.
     *
     * @return the oplockLevel
     */
    public final byte getOplockLevel() {
        return this.oplockLevel;
    }

    /**
     * Gets the file identifier.
     *
     * @return the fid
     */
    public final int getFid() {
        return this.fid;
    }

    /**
     * Gets the create action taken.
     *
     * @return the createAction
     */
    public final int getCreateAction() {
        return this.createAction;
    }

    /**
     * Gets the extended file attributes.
     *
     * @return the extFileAttributes
     */
    public final int getExtFileAttributes() {
        return this.extFileAttributes;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbBasicFileInfo#getAttributes()
     */
    @Override
    public int getAttributes() {
        return getExtFileAttributes();
    }

    /**
     * Gets the device state.
     *
     * @return the deviceState
     */
    public final int getDeviceState() {
        return this.deviceState;
    }

    /**
     * Gets the creation time.
     *
     * @return the creationTime
     */
    public final long getCreationTime() {
        return this.creationTime;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbBasicFileInfo#getCreateTime()
     */
    @Override
    public long getCreateTime() {
        return getCreationTime();
    }

    /**
     * @return the lastAccessTime
     */
    @Override
    public final long getLastAccessTime() {
        return this.lastAccessTime;
    }

    /**
     * @return the lastWriteTime
     */
    @Override
    public final long getLastWriteTime() {
        return this.lastWriteTime;
    }

    /**
     * Gets the allocation size.
     *
     * @return the allocationSize
     */
    public final long getAllocationSize() {
        return this.allocationSize;
    }

    /**
     * Gets the end of file position.
     *
     * @return the endOfFile
     */
    public final long getEndOfFile() {
        return this.endOfFile;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbBasicFileInfo#getSize()
     */
    @Override
    public long getSize() {
        return getEndOfFile();
    }

    @Override
    protected int writeParameterWordsWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    protected int writeBytesWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    protected int readParameterWordsWireFormat(final byte[] buffer, int bufferIndex) {
        final int start = bufferIndex;

        this.oplockLevel = buffer[bufferIndex];
        bufferIndex++;
        this.fid = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.createAction = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.creationTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.lastAccessTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.lastWriteTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.changeTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.extFileAttributes = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.allocationSize = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        this.endOfFile = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        this.fileType = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.deviceState = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.directory = (buffer[bufferIndex++] & 0xFF) > 0;
        return bufferIndex - start;
    }

    @Override
    protected int readBytesWireFormat(final byte[] buffer, final int bufferIndex) {
        return 0;
    }

    @Override
    public String toString() {
        return ("SmbComNTCreateAndXResponse[" + super.toString() + ",oplockLevel=" + this.oplockLevel + ",fid=" + this.fid
                + ",createAction=0x" + Hexdump.toHexString(this.createAction, 4) + ",creationTime=" + new Date(this.creationTime)
                + ",lastAccessTime=" + new Date(this.lastAccessTime) + ",lastWriteTime=" + new Date(this.lastWriteTime) + ",changeTime="
                + new Date(this.changeTime) + ",extFileAttributes=0x" + Hexdump.toHexString(this.extFileAttributes, 4) + ",allocationSize="
                + this.allocationSize + ",endOfFile=" + this.endOfFile + ",fileType=" + this.fileType + ",deviceState=" + this.deviceState
                + ",directory=" + this.directory + "]");
    }
}
