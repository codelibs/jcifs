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

class TransPeekNamedPipeResponse extends SmbComTransactionResponse {

    private final SmbNamedPipe pipe;
    static final int STATUS_DISCONNECTED = 1;
    static final int STATUS_LISTENING = 2;
    static final int STATUS_CONNECTION_OK = 3;
    static final int STATUS_SERVER_END_CLOSED = 4;

    int status, available;

    TransPeekNamedPipeResponse(final SmbNamedPipe pipe) {
        this.pipe = pipe;
    }

    @Override
    int writeSetupWireFormat(final byte[] dst, final int dstIndex) {
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
    int readSetupWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        return 0;
    }

    @Override
    int readParametersWireFormat(final byte[] buffer, int bufferIndex, final int len) {
        available = readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        int head = readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        status = readInt2(buffer, bufferIndex);
        return 6;
    }

    @Override
    int readDataWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        return 0;
    }

    @Override
    public String toString() {
        return ("TransPeekNamedPipeResponse[" + super.toString() + "]");
    }
}
