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

import org.codelibs.jcifs.smb1.util.Hexdump;

class Trans2QueryPathInformation extends SmbComTransaction {

    private final int informationLevel;

    Trans2QueryPathInformation(final String filename, final int informationLevel) {
        path = filename;
        this.informationLevel = informationLevel;
        command = SMB_COM_TRANSACTION2;
        subCommand = TRANS2_QUERY_PATH_INFORMATION;
        totalDataCount = 0;
        maxParameterCount = 2;
        maxDataCount = 40;
        maxSetupCount = (byte) 0x00;
    }

    @Override
    int writeSetupWireFormat(final byte[] dst, int dstIndex) {
        dst[dstIndex] = subCommand;
        dstIndex++;
        dst[dstIndex++] = (byte) 0x00;
        return 2;
    }

    @Override
    int writeParametersWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        writeInt2(informationLevel, dst, dstIndex);
        dstIndex += 2;
        dst[dstIndex] = (byte) 0x00;
        dstIndex++;
        dst[dstIndex++] = (byte) 0x00;
        dst[dstIndex++] = (byte) 0x00;
        dst[dstIndex++] = (byte) 0x00;
        dstIndex += writeString(path, dst, dstIndex);

        return dstIndex - start;
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
        return 0;
    }

    @Override
    int readDataWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        return 0;
    }

    @Override
    public String toString() {
        return ("Trans2QueryPathInformation[" + super.toString() + ",informationLevel=0x" + Hexdump.toHexString(informationLevel, 3)
                + ",filename=" + path + "]");
    }
}
