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
import org.codelibs.jcifs.smb.internal.smb1.AndXServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB1 Write AndX Response message.
 *
 * This response contains information about the write operation,
 * including the number of bytes actually written.
 */
public class SmbComWriteAndXResponse extends AndXServerMessageBlock {

    private long count;

    /**
     * Constructs a write response for SMB1 protocol.
     *
     * @param config the configuration for this SMB session
     */
    public SmbComWriteAndXResponse(final Configuration config) {
        super(config);
    }

    /**
     * Gets the number of bytes written.
     *
     * @return the count of bytes written
     */
    public final long getCount() {
        return this.count;
    }

    @Override
    protected int writeParameterWordsWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    protected int writeBytesWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    protected int readParameterWordsWireFormat(final byte[] buffer, final int bufferIndex) {
        this.count = SMBUtil.readInt2(buffer, bufferIndex) & 0xFFFFL;
        return 8;
    }

    @Override
    protected int readBytesWireFormat(final byte[] buffer, final int bufferIndex) {
        return 0;
    }

    @Override
    public String toString() {
        return ("SmbComWriteAndXResponse[" + super.toString() + ",count=" + this.count + "]");
    }
}
