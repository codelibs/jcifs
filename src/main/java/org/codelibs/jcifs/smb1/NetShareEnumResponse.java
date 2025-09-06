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

package org.codelibs.jcifs.smb1;

import org.codelibs.jcifs.smb1.util.LogStream;

class NetShareEnumResponse extends SmbComTransactionResponse {

    private int converter, totalAvailableEntries;

    NetShareEnumResponse() {
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
        SmbShareInfo e;

        useUnicode = false;

        results = new SmbShareInfo[numEntries];
        for (int i = 0; i < numEntries; i++) {
            results[i] = e = new SmbShareInfo();
            e.netName = readString(buffer, bufferIndex, 13, false);
            bufferIndex += 14;
            e.type = readInt2(buffer, bufferIndex);
            bufferIndex += 2;
            int off = readInt4(buffer, bufferIndex);
            bufferIndex += 4;
            off = (off & 0xFFFF) - converter;
            off = start + off;
            e.remark = readString(buffer, off, 128, false);

            if (LogStream.level >= 4) {
                log.println(e);
            }
        }

        return bufferIndex - start;
    }

    @Override
    public String toString() {
        return ("NetShareEnumResponse[" + super.toString() + ",status=" + status + ",converter=" + converter + ",entriesReturned="
                + numEntries + ",totalAvailableEntries=" + totalAvailableEntries + "]");
    }
}
