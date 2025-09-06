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

class Trans2FindNext2 extends SmbComTransaction {

    private final int sid, informationLevel;
    private int resumeKey;
    private final int flags;
    private String filename;

    Trans2FindNext2(final int sid, final int resumeKey, final String filename) {
        this.sid = sid;
        this.resumeKey = resumeKey;
        this.filename = filename;
        command = SMB_COM_TRANSACTION2;
        subCommand = TRANS2_FIND_NEXT2;
        informationLevel = Trans2FindFirst2.SMB_FILE_BOTH_DIRECTORY_INFO;
        flags = 0x00;
        maxParameterCount = 8;
        maxDataCount = Trans2FindFirst2.LIST_SIZE;
        maxSetupCount = 0;
    }

    @Override
    void reset(final int resumeKey, final String lastName) {
        super.reset();
        this.resumeKey = resumeKey;
        this.filename = lastName;
        flags2 = 0;
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

        writeInt2(sid, dst, dstIndex);
        dstIndex += 2;
        writeInt2(Trans2FindFirst2.LIST_COUNT, dst, dstIndex);
        dstIndex += 2;
        writeInt2(informationLevel, dst, dstIndex);
        dstIndex += 2;
        writeInt4(resumeKey, dst, dstIndex);
        dstIndex += 4;
        writeInt2(flags, dst, dstIndex);
        dstIndex += 2;
        dstIndex += writeString(filename, dst, dstIndex);

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
        return ("Trans2FindNext2[" + super.toString() + ",sid=" + sid + ",searchCount=" + Trans2FindFirst2.LIST_SIZE
                + ",informationLevel=0x" + Hexdump.toHexString(informationLevel, 3) + ",resumeKey=0x" + Hexdump.toHexString(resumeKey, 4)
                + ",flags=0x" + Hexdump.toHexString(flags, 2) + ",filename=" + filename + "]");
    }
}
