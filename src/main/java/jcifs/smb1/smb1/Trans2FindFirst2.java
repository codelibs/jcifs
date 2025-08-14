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

package jcifs.smb1.smb1;

import jcifs.smb1.Config;
import jcifs.smb1.util.Hexdump;

class Trans2FindFirst2 extends SmbComTransaction {

    // flags

    private static final int FLAGS_CLOSE_AFTER_THIS_REQUEST = 0x01;
    private static final int FLAGS_CLOSE_IF_END_REACHED = 0x02;
    private static final int FLAGS_RETURN_RESUME_KEYS = 0x04;
    private static final int FLAGS_RESUME_FROM_PREVIOUS_END = 0x08;
    private static final int FLAGS_FIND_WITH_BACKUP_INTENT = 0x10;

    private static final int DEFAULT_LIST_SIZE = 65535;
    private static final int DEFAULT_LIST_COUNT = 200;

    private final int searchAttributes;
    private final int flags;
    private final int informationLevel;
    private final int searchStorageType = 0;
    private final String wildcard;

    // information levels

    static final int SMB_INFO_STANDARD = 1;
    static final int SMB_INFO_QUERY_EA_SIZE = 2;
    static final int SMB_INFO_QUERY_EAS_FROM_LIST = 3;
    static final int SMB_FIND_FILE_DIRECTORY_INFO = 0x101;
    static final int SMB_FIND_FILE_FULL_DIRECTORY_INFO = 0x102;
    static final int SMB_FILE_NAMES_INFO = 0x103;
    static final int SMB_FILE_BOTH_DIRECTORY_INFO = 0x104;

    static final int LIST_SIZE = Config.getInt("jcifs.smb1.smb.client.listSize", DEFAULT_LIST_SIZE);
    static final int LIST_COUNT = Config.getInt("jcifs.smb1.smb.client.listCount", DEFAULT_LIST_COUNT);

    Trans2FindFirst2(final String filename, final String wildcard, final int searchAttributes) {
        if (filename.equals("\\")) {
            this.path = filename;
        } else {
            this.path = filename + "\\";
        }
        this.wildcard = wildcard;
        this.searchAttributes = searchAttributes & 0x37; /* generally ignored tho */
        command = SMB_COM_TRANSACTION2;
        subCommand = TRANS2_FIND_FIRST2;

        flags = 0x00;
        informationLevel = SMB_FILE_BOTH_DIRECTORY_INFO;

        totalDataCount = 0;
        maxParameterCount = 10;
        maxDataCount = LIST_SIZE;
        maxSetupCount = 0;
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

        writeInt2(searchAttributes, dst, dstIndex);
        dstIndex += 2;
        writeInt2(LIST_COUNT, dst, dstIndex);
        dstIndex += 2;
        writeInt2(flags, dst, dstIndex);
        dstIndex += 2;
        writeInt2(informationLevel, dst, dstIndex);
        dstIndex += 2;
        writeInt4(searchStorageType, dst, dstIndex);
        dstIndex += 4;
        dstIndex += writeString(path + wildcard, dst, dstIndex);

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
        return ("Trans2FindFirst2[" + super.toString() + ",searchAttributes=0x" + Hexdump.toHexString(searchAttributes, 2) + ",searchCount="
                + LIST_COUNT + ",flags=0x" + Hexdump.toHexString(flags, 2) + ",informationLevel=0x"
                + Hexdump.toHexString(informationLevel, 3) + ",searchStorageType=" + searchStorageType + ",filename=" + path + "]");
    }
}
