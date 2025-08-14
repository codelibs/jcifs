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

class SmbComClose extends ServerMessageBlock {

    private final int fid;
    private final long lastWriteTime;

    SmbComClose(final int fid, final long lastWriteTime) {
        this.fid = fid;
        this.lastWriteTime = lastWriteTime;
        command = SMB_COM_CLOSE;
    }

    @Override
    int writeParameterWordsWireFormat(final byte[] dst, int dstIndex) {
        writeInt2(fid, dst, dstIndex);
        dstIndex += 2;
        writeUTime(lastWriteTime, dst, dstIndex);
        return 6;
    }

    @Override
    int writeBytesWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
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
        return ("SmbComClose[" + super.toString() + ",fid=" + fid + ",lastWriteTime=" + lastWriteTime + "]");
    }
}
