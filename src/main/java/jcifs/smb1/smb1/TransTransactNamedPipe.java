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

import jcifs.smb1.util.LogStream;

class TransTransactNamedPipe extends SmbComTransaction {

    private final byte[] pipeData;
    private final int pipeFid, pipeDataOff, pipeDataLen;

    TransTransactNamedPipe(final int fid, final byte[] data, final int off, final int len) {
        pipeFid = fid;
        pipeData = data;
        pipeDataOff = off;
        pipeDataLen = len;
        command = SMB_COM_TRANSACTION;
        subCommand = TRANS_TRANSACT_NAMED_PIPE;
        maxParameterCount = 0;
        maxDataCount = 0xFFFF;
        maxSetupCount = (byte) 0x00;
        setupCount = 2;
        name = "\\PIPE\\";
    }

    @Override
    int writeSetupWireFormat(final byte[] dst, int dstIndex) {
        dst[dstIndex] = subCommand;
        dstIndex++;
        dst[dstIndex++] = (byte) 0x00;
        writeInt2(pipeFid, dst, dstIndex);
        dstIndex += 2;
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
        if (dst.length - dstIndex < pipeDataLen) {
            if (LogStream.level >= 3) {
                log.println("TransTransactNamedPipe data too long for buffer");
            }
            return 0;
        }
        System.arraycopy(pipeData, pipeDataOff, dst, dstIndex, pipeDataLen);
        return pipeDataLen;
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
        return ("TransTransactNamedPipe[" + super.toString() + ",pipeFid=" + pipeFid + "]");
    }
}
