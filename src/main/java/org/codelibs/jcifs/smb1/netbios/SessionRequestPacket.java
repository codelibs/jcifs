/* org.codelibs.jcifs.smb smb client library in Java
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

package org.codelibs.jcifs.smb1.netbios;

import java.io.IOException;
import java.io.InputStream;

/**
 * NetBIOS session request packet for establishing sessions.
 * This packet is sent to request a NetBIOS session with a remote host.
 */
public class SessionRequestPacket extends SessionServicePacket {

    private final Name calledName, callingName;

    SessionRequestPacket() {
        calledName = new Name();
        callingName = new Name();
    }

    /**
     * Constructs a NetBIOS session request packet.
     *
     * @param calledName the NetBIOS name of the called (destination) host
     * @param callingName the NetBIOS name of the calling (source) host
     */
    public SessionRequestPacket(final Name calledName, final Name callingName) {
        type = SESSION_REQUEST;
        this.calledName = calledName;
        this.callingName = callingName;
    }

    @Override
    int writeTrailerWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        dstIndex += calledName.writeWireFormat(dst, dstIndex);
        dstIndex += callingName.writeWireFormat(dst, dstIndex);
        return dstIndex - start;
    }

    @Override
    int readTrailerWireFormat(final InputStream in, final byte[] buffer, int bufferIndex) throws IOException {
        final int start = bufferIndex;
        if (in.read(buffer, bufferIndex, length) != length) {
            throw new IOException("invalid session request wire format");
        }
        bufferIndex += calledName.readWireFormat(buffer, bufferIndex);
        bufferIndex += callingName.readWireFormat(buffer, bufferIndex);
        return bufferIndex - start;
    }
}
