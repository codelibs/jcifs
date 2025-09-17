/* org.codelibs.jcifs.smb smb client library in Java
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

package org.codelibs.jcifs.smb1;

import java.util.Date;

import org.codelibs.jcifs.smb1.util.Hexdump;

class Trans2QueryPathInformationResponse extends SmbComTransactionResponse {

    // information levels
    static final int SMB_QUERY_FILE_BASIC_INFO = 0x101;
    static final int SMB_QUERY_FILE_STANDARD_INFO = 0x102;

    class SmbQueryFileBasicInfo implements Info {
        long createTime;
        long lastAccessTime;
        long lastWriteTime;
        long changeTime;
        int attributes;

        @Override
        public int getAttributes() {
            return attributes;
        }

        @Override
        public long getCreateTime() {
            return createTime;
        }

        @Override
        public long getLastWriteTime() {
            return lastWriteTime;
        }

        @Override
        public long getSize() {
            return 0L;
        }

        @Override
        public String toString() {
            return ("SmbQueryFileBasicInfo[" + "createTime=" + new Date(createTime) + ",lastAccessTime=" + new Date(lastAccessTime)
                    + ",lastWriteTime=" + new Date(lastWriteTime) + ",changeTime=" + new Date(changeTime) + ",attributes=0x"
                    + Hexdump.toHexString(attributes, 4) + "]");
        }
    }

    class SmbQueryFileStandardInfo implements Info {
        long allocationSize;
        long endOfFile;
        int numberOfLinks;
        boolean deletePending;
        boolean directory;

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
        public long getSize() {
            return endOfFile;
        }

        @Override
        public String toString() {
            return ("SmbQueryInfoStandard[" + "allocationSize=" + allocationSize + ",endOfFile=" + endOfFile + ",numberOfLinks="
                    + numberOfLinks + ",deletePending=" + deletePending + ",directory=" + directory + "]");
        }
    }

    private final int informationLevel;

    Info info;

    Trans2QueryPathInformationResponse(final int informationLevel) {
        this.informationLevel = informationLevel;
        subCommand = SmbComTransaction.TRANS2_QUERY_PATH_INFORMATION;
    }

    @Override
    int writeSetupWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    int writeParametersWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    int writeDataWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    int readSetupWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        return 0;
    }

    @Override
    int readParametersWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        // observed two zero bytes here with at least win98
        return 2;
    }

    @Override
    int readDataWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        return switch (informationLevel) {
        case SMB_QUERY_FILE_BASIC_INFO -> readSmbQueryFileBasicInfoWireFormat(buffer, bufferIndex);
        case SMB_QUERY_FILE_STANDARD_INFO -> readSmbQueryFileStandardInfoWireFormat(buffer, bufferIndex);
        default -> 0;
        };
    }

    int readSmbQueryFileStandardInfoWireFormat(final byte[] buffer, int bufferIndex) {
        final int start = bufferIndex;

        final SmbQueryFileStandardInfo info = new SmbQueryFileStandardInfo();
        info.allocationSize = readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        info.endOfFile = readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        info.numberOfLinks = readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        info.deletePending = (buffer[bufferIndex] & 0xFF) > 0;
        bufferIndex++;
        info.directory = (buffer[bufferIndex++] & 0xFF) > 0;
        this.info = info;

        return bufferIndex - start;
    }

    int readSmbQueryFileBasicInfoWireFormat(final byte[] buffer, int bufferIndex) {
        final int start = bufferIndex;

        final SmbQueryFileBasicInfo info = new SmbQueryFileBasicInfo();
        info.createTime = readTime(buffer, bufferIndex);
        bufferIndex += 8;
        info.lastAccessTime = readTime(buffer, bufferIndex);
        bufferIndex += 8;
        info.lastWriteTime = readTime(buffer, bufferIndex);
        bufferIndex += 8;
        info.changeTime = readTime(buffer, bufferIndex);
        bufferIndex += 8;
        info.attributes = readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.info = info;

        return bufferIndex - start;
    }

    @Override
    public String toString() {
        return ("Trans2QueryPathInformationResponse[" + super.toString() + "]");
    }
}
