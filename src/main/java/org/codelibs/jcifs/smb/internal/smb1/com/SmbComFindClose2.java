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
 * SMB1 Find Close2 request message.
 *
 * This command is used to close a search handle that was
 * opened by a Trans2 Find First2 request.
 */
public class SmbComFindClose2 extends ServerMessageBlock {

    private final int sid;

    /**
     * Creates a new SMB1 find close request to close a search handle.
     *
     * @param config the CIFS configuration
     * @param sid the search identifier to close
     */
    public SmbComFindClose2(final Configuration config, final int sid) {
        super(config, SMB_COM_FIND_CLOSE2);
        this.sid = sid;
    }

    @Override
    protected int writeParameterWordsWireFormat(final byte[] dst, final int dstIndex) {
        SMBUtil.writeInt2(this.sid, dst, dstIndex);
        return 2;
    }

    @Override
    protected int writeBytesWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
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
        return ("SmbComFindClose2[" + super.toString() + ",sid=" + this.sid + "]");
    }
}
