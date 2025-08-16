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

package jcifs.internal.smb1.com;

import jcifs.Configuration;
import jcifs.SmbConstants;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;

/**
 * SMB1 Delete file request message.
 *
 * This command is used to delete a file on the server.
 * The file must not be in use before it can be deleted.
 */
public class SmbComDelete extends ServerMessageBlock {

    private final int searchAttributes;

    /**
     * Creates a new SMB1 delete file request.
     *
     * @param config the CIFS configuration
     * @param path the path of the file to delete
     */
    public SmbComDelete(final Configuration config, final String path) {
        super(config, SMB_COM_DELETE, path);
        this.searchAttributes = SmbConstants.ATTR_HIDDEN | SmbConstants.ATTR_HIDDEN | SmbConstants.ATTR_SYSTEM;
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
        dstIndex += writeString(this.path, dst, dstIndex);

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
        return ("SmbComDelete[" + super.toString() + ",searchAttributes=0x" + Hexdump.toHexString(this.searchAttributes, 4) + ",fileName="
                + this.path + "]");
    }
}
