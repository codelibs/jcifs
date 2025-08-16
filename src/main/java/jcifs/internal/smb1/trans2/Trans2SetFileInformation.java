/* jcifs smb client library in Java
 * Copyright (C) 2003  "Michael B. Allen" <jcifs at samba dot org>
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

package jcifs.internal.smb1.trans2;

import jcifs.Configuration;
import jcifs.internal.fscc.FileBasicInfo;
import jcifs.internal.fscc.FileInformation;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.util.SMBUtil;

/**
 * Trans2 SetFileInformation request message for modifying file metadata.
 * This class implements the TRANS2_SET_FILE_INFORMATION transaction to update
 * file attributes, timestamps, and other metadata properties.
 */
public class Trans2SetFileInformation extends SmbComTransaction {

    private final int fid;
    private final FileInformation info;

    /**
     * Constructs a Trans2SetFileInformation request with file information object.
     *
     * @param config the SMB configuration
     * @param fid the file identifier
     * @param info the file information to set
     */
    public Trans2SetFileInformation(final Configuration config, final int fid, final FileInformation info) {
        super(config, SMB_COM_TRANSACTION2, TRANS2_SET_FILE_INFORMATION);
        this.fid = fid;
        this.info = info;
        this.maxParameterCount = 6;
        this.maxDataCount = 0;
        this.maxSetupCount = (byte) 0x00;
    }

    /**
     * Constructs a Trans2SetFileInformation request with specific file attributes and timestamps.
     *
     * @param config the SMB configuration
     * @param fid the file identifier
     * @param attributes the file attributes to set
     * @param createTime the file creation time
     * @param lastWriteTime the last write time
     * @param lastAccessTime the last access time
     */
    public Trans2SetFileInformation(final Configuration config, final int fid, final int attributes, final long createTime,
            final long lastWriteTime, final long lastAccessTime) {
        this(config, fid, new FileBasicInfo(createTime, lastAccessTime, lastWriteTime, 0L, attributes | 0x80));
    }

    @Override
    protected int writeSetupWireFormat(final byte[] dst, int dstIndex) {
        dst[dstIndex] = this.getSubCommand();
        dstIndex++;
        dst[dstIndex++] = (byte) 0x00;
        return 2;
    }

    @Override
    protected int writeParametersWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        SMBUtil.writeInt2(this.fid, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(Trans2QueryPathInformation.mapInformationLevel(this.info.getFileInformationLevel()), dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(0, dst, dstIndex);
        dstIndex += 2;

        return dstIndex - start;
    }

    @Override
    protected int writeDataWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        dstIndex += this.info.encode(dst, dstIndex);

        /* 6 zeros observed with NT */
        SMBUtil.writeInt8(0L, dst, dstIndex);
        dstIndex += 6;

        /*
         * Also observed 4 byte alignment but we stick
         * with the default for jCIFS which is 2
         */

        return dstIndex - start;
    }

    @Override
    protected int readSetupWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        return 0;
    }

    @Override
    protected int readParametersWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        return 0;
    }

    @Override
    protected int readDataWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        return 0;
    }

    @Override
    public String toString() {
        return ("Trans2SetFileInformation[" + super.toString() + ",fid=" + this.fid + "]");
    }
}
