/*
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

package org.codelibs.jcifs.smb.internal.smb1.com;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.SmbBasicFileInfo;
import org.codelibs.jcifs.smb.internal.smb1.AndXServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB1 Open AndX Response message.
 *
 * This response contains information about the opened file,
 * including file ID, attributes, size, and access permissions.
 */
public class SmbComOpenAndXResponse extends AndXServerMessageBlock implements SmbBasicFileInfo {

    private int fid, fileAttributes, fileDataSize, grantedAccess, fileType, deviceState, action, serverFid;
    private long lastWriteTime;

    /**
     * Constructs an Open AndX response.
     *
     * @param config the configuration
     */
    public SmbComOpenAndXResponse(final Configuration config) {
        super(config);
    }

    /**
     * Constructs an Open AndX response with a chained response.
     *
     * @param config the configuration
     * @param andxResp the chained seek response
     */
    public SmbComOpenAndXResponse(final Configuration config, final SmbComSeekResponse andxResp) {
        super(config, andxResp);
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
     * Gets the file data size.
     *
     * @return the dataSize
     */
    public final int getDataSize() {
        return this.fileDataSize;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.SmbBasicFileInfo#getSize()
     */
    @Override
    public long getSize() {
        return getDataSize();
    }

    /**
     * Gets the granted access rights.
     *
     * @return the grantedAccess
     */
    public final int getGrantedAccess() {
        return this.grantedAccess;
    }

    /**
     * Gets the file attributes.
     *
     * @return the fileAttributes
     */
    public final int getFileAttributes() {
        return this.fileAttributes;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.SmbBasicFileInfo#getAttributes()
     */
    @Override
    public int getAttributes() {
        return getFileAttributes();
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
     * Gets the device state.
     *
     * @return the deviceState
     */
    public final int getDeviceState() {
        return this.deviceState;
    }

    /**
     * Gets the action taken.
     *
     * @return the action
     */
    public final int getAction() {
        return this.action;
    }

    /**
     * Gets the server file identifier.
     *
     * @return the serverFid
     */
    public final int getServerFid() {
        return this.serverFid;
    }

    /**
     * @return the lastWriteTime
     */
    @Override
    public final long getLastWriteTime() {
        return this.lastWriteTime;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.SmbBasicFileInfo#getCreateTime()
     */
    @Override
    public long getCreateTime() {
        return 0;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.SmbBasicFileInfo#getLastAccessTime()
     */
    @Override
    public long getLastAccessTime() {
        return 0;
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

        this.fid = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.fileAttributes = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.lastWriteTime = SMBUtil.readUTime(buffer, bufferIndex);
        bufferIndex += 4;
        this.fileDataSize = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.grantedAccess = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.fileType = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.deviceState = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.action = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.serverFid = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 6;

        return bufferIndex - start;
    }

    @Override
    protected int readBytesWireFormat(final byte[] buffer, final int bufferIndex) {
        return 0;
    }

    @Override
    public String toString() {
        return ("SmbComOpenAndXResponse[" + super.toString() + ",fid=" + this.fid + ",fileAttributes=" + this.fileAttributes
                + ",lastWriteTime=" + this.lastWriteTime + ",dataSize=" + this.fileDataSize + ",grantedAccess=" + this.grantedAccess
                + ",fileType=" + this.fileType + ",deviceState=" + this.deviceState + ",action=" + this.action + ",serverFid="
                + this.serverFid + "]");
    }
}
