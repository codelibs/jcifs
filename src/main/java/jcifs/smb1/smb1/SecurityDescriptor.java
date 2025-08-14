/* jcifs smb client library in Java
 * Copyright (C) 2005  "Michael B. Allen" <jcifs at samba dot org>
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

import java.io.IOException;

public class SecurityDescriptor {

    SID owner_user, owner_group;
    public int type;
    public ACE[] aces;

    public SecurityDescriptor() {
    }

    public SecurityDescriptor(final byte[] buffer, final int bufferIndex, final int len) throws IOException {
        this.decode(buffer, bufferIndex, len);
    }

    public int decode(final byte[] buffer, int bufferIndex, final int len) throws IOException {
        final int start = bufferIndex;

        bufferIndex++; // revision
        bufferIndex++;
        type = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        final int ownerUOffset = ServerMessageBlock.readInt4(buffer, bufferIndex); // offset to owner sid
        bufferIndex += 4;
        final int ownerGOffset = ServerMessageBlock.readInt4(buffer, bufferIndex); // offset to group sid
        bufferIndex += 4;
        final int saclOffset = ServerMessageBlock.readInt4(buffer, bufferIndex); // offset to sacl
        bufferIndex += 4;
        final int daclOffset = ServerMessageBlock.readInt4(buffer, bufferIndex);

        if (ownerUOffset > 0) {
            bufferIndex = start + ownerUOffset;
            owner_user = new SID(buffer, bufferIndex);
            bufferIndex += 28; // ???
        }

        if (ownerGOffset > 0) {
            bufferIndex = start + ownerGOffset;
            owner_group = new SID(buffer, bufferIndex);
            bufferIndex += 28; // ???
        }

        bufferIndex = start + daclOffset;

        if (daclOffset != 0) {
            bufferIndex++; // revision
            bufferIndex++;
            final int size = ServerMessageBlock.readInt2(buffer, bufferIndex);
            bufferIndex += 2;
            final int numAces = ServerMessageBlock.readInt4(buffer, bufferIndex);
            bufferIndex += 4;

            if (numAces > 4096) {
                throw new IOException("Invalid SecurityDescriptor");
            }

            aces = new ACE[numAces];
            for (int i = 0; i < numAces; i++) {
                aces[i] = new ACE();
                bufferIndex += aces[i].decode(buffer, bufferIndex);
            }
        } else {
            aces = null;
        }

        return bufferIndex - start;
    }

    @Override
    public String toString() {
        StringBuilder ret = new StringBuilder("SecurityDescriptor:\n");
        if (aces != null) {
            for (final ACE element : aces) {
                ret.append(element.toString()).append("\n");
            }
        } else {
            ret.append("NULL");
        }
        return ret.toString();
    }
}
