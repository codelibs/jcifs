/* jcifs smb client library in Java
 * Copyright (C) 2003  "Michael B. Allen" <jcifs at samba dot org>
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

class SmbComWrite extends ServerMessageBlock {

    private int fid, count, offset, remaining, off;
    private byte[] b;

    SmbComWrite() {
        command = SMB_COM_WRITE;
    }

    SmbComWrite(final int fid, final int offset, final int remaining, final byte[] b, final int off, final int len) {
        this.fid = fid;
        this.count = len;
        this.offset = offset;
        this.remaining = remaining;
        this.b = b;
        this.off = off;
        command = SMB_COM_WRITE;
    }

    void setParam(final int fid, final long offset, final int remaining, final byte[] b, final int off, final int len) {
        this.fid = fid;
        this.offset = (int) (offset & 0xFFFFFFFFL);
        this.remaining = remaining;
        this.b = b;
        this.off = off;
        count = len;
        digest = null; /* otherwise recycled commands
                        * like writeandx will choke if session
                        * closes in between */
    }

    @Override
    int writeParameterWordsWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        writeInt2(fid, dst, dstIndex);
        dstIndex += 2;
        writeInt2(count, dst, dstIndex);
        dstIndex += 2;
        writeInt4(offset, dst, dstIndex);
        dstIndex += 4;
        writeInt2(remaining, dst, dstIndex);
        dstIndex += 2;

        return dstIndex - start;
    }

    @Override
    int writeBytesWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        dst[dstIndex] = (byte) 0x01; /* BufferFormat */
        dstIndex++;
        writeInt2(count, dst, dstIndex); /* DataLength? */
        dstIndex += 2;
        System.arraycopy(b, off, dst, dstIndex, count);
        dstIndex += count;

        return dstIndex - start;
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
        return ("SmbComWrite[" + super.toString() + ",fid=" + fid + ",count=" + count + ",offset=" + offset + ",remaining=" + remaining
                + "]");
    }
}
