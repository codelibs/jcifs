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
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB1 COM_SET_INFORMATION command implementation.
 *
 * This command sets file attributes and last write time for a file or directory.
 *
 * @author mbechler
 */
public class SmbComSetInformation extends ServerMessageBlock {

    private final int fileAttributes;
    private final long lastWriteTime;

    /**
     * Constructs a set information request to modify file attributes and modification time.
     *
     * @param config the configuration to use
     * @param filename the name of the file to modify
     * @param attrs the file attributes to set
     * @param mtime the modification time to set in milliseconds since epoch
     */
    public SmbComSetInformation(final Configuration config, final String filename, final int attrs, final long mtime) {
        super(config, SMB_COM_SET_INFORMATION, filename);
        this.fileAttributes = attrs;
        this.lastWriteTime = mtime;
    }

    @Override
    protected int writeParameterWordsWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        SMBUtil.writeInt2(this.fileAttributes, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeUTime(this.lastWriteTime, dst, dstIndex);
        dstIndex += 4;
        // reserved
        dstIndex += 10;
        return dstIndex - start;
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
        return ("SmbComSetInformation[" + super.toString() + ",filename=" + this.path + ",fileAttributes=" + this.fileAttributes
                + ",lastWriteTime=" + this.lastWriteTime + "]");
    }
}
