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

package org.codelibs.jcifs.smb1;

class SmbComReadAndXResponse extends AndXServerMessageBlock {

    byte[] b;
    int off, dataCompactionMode, dataLength, dataOffset;

    SmbComReadAndXResponse() {
    }

    SmbComReadAndXResponse(final byte[] b, final int off) {
        this.b = b;
        this.off = off;
    }

    void setParam(final byte[] b, final int off) {
        this.b = b;
        this.off = off;
    }

    @Override
    int writeParameterWordsWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    int writeBytesWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    int readParameterWordsWireFormat(final byte[] buffer, int bufferIndex) {
        final int start = bufferIndex;

        bufferIndex += 2; // reserved
        dataCompactionMode = readInt2(buffer, bufferIndex);
        bufferIndex += 4; // 2 reserved
        dataLength = readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        dataOffset = readInt2(buffer, bufferIndex);
        bufferIndex += 12; // 10 reserved

        return bufferIndex - start;
    }

    @Override
    int readBytesWireFormat(final byte[] buffer, final int bufferIndex) {
        // handled special in SmbTransport.doRecv()
        return 0;
    }

    @Override
    public String toString() {
        return ("SmbComReadAndXResponse[" + super.toString() + ",dataCompactionMode=" + dataCompactionMode + ",dataLength=" + dataLength
                + ",dataOffset=" + dataOffset + "]");
    }
}
