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
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.codelibs.jcifs.smb.util.Hexdump;

/**
 * SMB1 COM_RENAME command implementation.
 *
 * This command renames a file or directory on the SMB server.
 * It takes an old filename and new filename and performs the rename operation.
 */
public class SmbComRename extends ServerMessageBlock {

    private final int searchAttributes;
    private final String oldFileName;
    private final String newFileName;

    /**
     * Constructs a rename request.
     *
     * @param config the configuration
     * @param oldFileName the current file name
     * @param newFileName the new file name
     */
    public SmbComRename(final Configuration config, final String oldFileName, final String newFileName) {
        super(config, SMB_COM_RENAME);
        this.oldFileName = oldFileName;
        this.newFileName = newFileName;
        this.searchAttributes = SmbConstants.ATTR_HIDDEN | SmbConstants.ATTR_SYSTEM | SmbConstants.ATTR_DIRECTORY;
    }

    @Override
    protected int writeParameterWordsWireFormat(final byte[] dst, final int dstIndex) {
        SMBUtil.writeInt2(this.searchAttributes, dst, dstIndex);
        return 2;
    }

    @Override
    protected int writeBytesWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        dst[dstIndex] = (byte) 0x04;
        dstIndex++;
        dstIndex += writeString(this.oldFileName, dst, dstIndex);
        dst[dstIndex++] = (byte) 0x04;
        if (this.isUseUnicode()) {
            dst[dstIndex++] = (byte) '\0';
        }
        dstIndex += writeString(this.newFileName, dst, dstIndex);

        return dstIndex - start;
    }

    @Override
    protected int readParameterWordsWireFormat(final byte[] buffer, final int bufferIndex) {
        return 0;
    }

    @Override
    protected int readBytesWireFormat(final byte[] buffer, final int bufferIndex) {
        return 0;
    }

    @Override
    public String toString() {
        return ("SmbComRename[" + super.toString() + ",searchAttributes=0x" + Hexdump.toHexString(this.searchAttributes, 4)
                + ",oldFileName=" + this.oldFileName + ",newFileName=" + this.newFileName + "]");
    }
}
