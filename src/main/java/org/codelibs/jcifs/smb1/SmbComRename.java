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

import org.codelibs.jcifs.smb1.util.Hexdump;

class SmbComRename extends ServerMessageBlock {

    private final int searchAttributes;
    private final String oldFileName;
    private final String newFileName;

    SmbComRename(final String oldFileName, final String newFileName) {
        command = SMB_COM_RENAME;
        this.oldFileName = oldFileName;
        this.newFileName = newFileName;
        searchAttributes = ATTR_HIDDEN | ATTR_SYSTEM | ATTR_DIRECTORY;
    }

    @Override
    int writeParameterWordsWireFormat(final byte[] dst, final int dstIndex) {
        writeInt2(searchAttributes, dst, dstIndex);
        return 2;
    }

    @Override
    int writeBytesWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        dst[dstIndex] = (byte) 0x04;
        dstIndex++;
        dstIndex += writeString(oldFileName, dst, dstIndex);
        dst[dstIndex++] = (byte) 0x04;
        if (useUnicode) {
            dst[dstIndex++] = (byte) '\0';
        }
        dstIndex += writeString(newFileName, dst, dstIndex);

        return dstIndex - start;
    }

    @Override
    int readParameterWordsWireFormat(final byte[] buffer, final int bufferIndex) {
        return 0;
    }

    @Override
    int readBytesWireFormat(final byte[] buffer, final int bufferIndex) {
        return 0;
    }

    @Override
    public String toString() {
        return ("SmbComRename[" + super.toString() + ",searchAttributes=0x" + Hexdump.toHexString(searchAttributes, 4) + ",oldFileName="
                + oldFileName + ",newFileName=" + newFileName + "]");
    }
}
