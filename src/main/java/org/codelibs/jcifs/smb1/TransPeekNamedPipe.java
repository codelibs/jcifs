/*
 * Copyright (C) 2002  "Michael B. Allen" <jcifs at samba dot org>
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

class TransPeekNamedPipe extends SmbComTransaction {

    private final int fid;

    TransPeekNamedPipe(final String pipeName, final int fid) {
        name = pipeName;
        this.fid = fid;
        command = SMB_COM_TRANSACTION;
        subCommand = TRANS_PEEK_NAMED_PIPE;
        timeout = 0xFFFFFFFF;
        maxParameterCount = 6;
        maxDataCount = 1;
        maxSetupCount = (byte) 0x00;
        setupCount = 2;
    }

    @Override
    int writeSetupWireFormat(final byte[] dst, int dstIndex) {
        dst[dstIndex] = subCommand;
        dstIndex++;
        dst[dstIndex++] = (byte) 0x00;
        // this says "Transaction priority" in netmon
        writeInt2(fid, dst, dstIndex);
        return 4;
    }

    @Override
    int readSetupWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
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
    int readParametersWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        return 0;
    }

    @Override
    int readDataWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        return 0;
    }

    @Override
    public String toString() {
        return ("TransPeekNamedPipe[" + super.toString() + ",pipeName=" + name + "]");
    }
}
