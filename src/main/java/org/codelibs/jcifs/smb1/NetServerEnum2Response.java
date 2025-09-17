/* org.codelibs.jcifs.smb smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
 *                             Gary Rambo <grambo aventail.com>
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

import org.codelibs.jcifs.smb1.util.Hexdump;
import org.codelibs.jcifs.smb1.util.LogStream;

class NetServerEnum2Response extends SmbComTransactionResponse {

    class ServerInfo1 implements FileEntry {
        String name;
        int versionMajor;
        int versionMinor;
        int type;
        String commentOrMasterBrowser;

        @Override
        public String getName() {
            return name;
        }

        @Override
        public int getType() {
            return (type & 0x80000000) != 0 ? SmbFile.TYPE_WORKGROUP : SmbFile.TYPE_SERVER;
        }

        @Override
        public int getAttributes() {
            return SmbFile.ATTR_READONLY | SmbFile.ATTR_DIRECTORY;
        }

        @Override
        public long createTime() {
            return 0L;
        }

        @Override
        public long lastModified() {
            return 0L;
        }

        @Override
        public long length() {
            return 0L;
        }

        @Override
        public String toString() {
            return ("ServerInfo1[" + "name=" + name + ",versionMajor=" + versionMajor + ",versionMinor=" + versionMinor + ",type=0x"
                    + Hexdump.toHexString(type, 8) + ",commentOrMasterBrowser=" + commentOrMasterBrowser + "]");
        }
    }

    private int converter, totalAvailableEntries;

    String lastName;

    NetServerEnum2Response() {
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
    int readParametersWireFormat(final byte[] buffer, int bufferIndex, final int len) {
        final int start = bufferIndex;

        status = readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        converter = readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        numEntries = readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        totalAvailableEntries = readInt2(buffer, bufferIndex);
        bufferIndex += 2;

        return bufferIndex - start;
    }

    @Override
    int readDataWireFormat(final byte[] buffer, int bufferIndex, final int len) {
        final int start = bufferIndex;
        ServerInfo1 e = null;

        results = new ServerInfo1[numEntries];
        for (int i = 0; i < numEntries; i++) {
            results[i] = e = new ServerInfo1();
            e.name = readString(buffer, bufferIndex, 16, false);
            bufferIndex += 16;
            e.versionMajor = buffer[bufferIndex] & 0xFF;
            bufferIndex++;
            e.versionMinor = buffer[bufferIndex++] & 0xFF;
            e.type = readInt4(buffer, bufferIndex);
            bufferIndex += 4;
            int off = readInt4(buffer, bufferIndex);
            bufferIndex += 4;
            off = (off & 0xFFFF) - converter;
            off = start + off;
            e.commentOrMasterBrowser = readString(buffer, off, 48, false);

            if (LogStream.level >= 4) {
                log.println(e);
            }
        }
        lastName = numEntries == 0 ? null : e.name;

        return bufferIndex - start;
    }

    @Override
    public String toString() {
        return ("NetServerEnum2Response[" + super.toString() + ",status=" + status + ",converter=" + converter + ",entriesReturned="
                + numEntries + ",totalAvailableEntries=" + totalAvailableEntries + ",lastName=" + lastName + "]");
    }
}
