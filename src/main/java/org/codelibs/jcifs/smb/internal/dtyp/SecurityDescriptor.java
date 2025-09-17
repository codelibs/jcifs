/* org.codelibs.jcifs.smb smb client library in Java
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

package org.codelibs.jcifs.smb.internal.dtyp;

import java.io.IOException;

import org.codelibs.jcifs.smb.impl.SID;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * Internal use only
 *
 *
 * <p>This class is intended for internal use.</p>
 */
public class SecurityDescriptor implements SecurityInfo {

    /**
     * Descriptor type
     */
    private int type;

    /**
     * ACEs
     */
    private ACE[] aces;
    private SID ownerUserSid, ownerGroupSid;

    /**
     * Creates an empty security descriptor.
     */
    public SecurityDescriptor() {
    }

    /**
     * Creates a security descriptor by decoding from a byte buffer.
     *
     * @param buffer the byte buffer containing the security descriptor data
     * @param bufferIndex the starting offset in the buffer
     * @param len the length of data to decode
     * @throws IOException if an I/O error occurs during decoding
     */
    public SecurityDescriptor(final byte[] buffer, final int bufferIndex, final int len) throws IOException {
        this.decode(buffer, bufferIndex, len);
    }

    /**
     * Gets the type flags of this security descriptor.
     *
     * @return the type flags indicating security descriptor control flags
     */
    public final int getType() {
        return this.type;
    }

    /**
     * Gets the access control entries (ACEs) from this security descriptor.
     *
     * @return the array of access control entries
     */
    public final ACE[] getAces() {
        return this.aces;
    }

    /**
     * Gets the owner group SID of this security descriptor.
     *
     * @return the security identifier of the owner group
     */
    public final SID getOwnerGroupSid() {
        return this.ownerGroupSid;
    }

    /**
     * Gets the owner user SID of this security descriptor.
     *
     * @return the security identifier of the owner user
     */
    public final SID getOwnerUserSid() {
        return this.ownerUserSid;
    }

    /**
     * Decodes a security descriptor from a byte buffer.
     *
     * @param buffer the byte buffer containing the security descriptor data
     * @param bufferIndex the starting offset in the buffer
     * @param len the length of data to decode
     * @return the number of bytes decoded
     * @throws SMBProtocolDecodingException if the data cannot be properly decoded
     */
    @Override
    public int decode(final byte[] buffer, int bufferIndex, final int len) throws SMBProtocolDecodingException {
        final int start = bufferIndex;

        bufferIndex++; // revision
        bufferIndex++;
        this.type = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        final int ownerUOffset = SMBUtil.readInt4(buffer, bufferIndex); // offset to owner sid
        bufferIndex += 4;
        final int ownerGOffset = SMBUtil.readInt4(buffer, bufferIndex); // offset to group sid
        bufferIndex += 4;
        SMBUtil.readInt4(buffer, bufferIndex); // offset to sacl
        bufferIndex += 4;
        final int daclOffset = SMBUtil.readInt4(buffer, bufferIndex);

        if (ownerUOffset > 0) {
            bufferIndex = start + ownerUOffset;
            this.ownerUserSid = new SID(buffer, bufferIndex);
            bufferIndex += 8 + 4 * this.ownerUserSid.sub_authority_count;
        }

        if (ownerGOffset > 0) {
            bufferIndex = start + ownerGOffset;
            this.ownerGroupSid = new SID(buffer, bufferIndex);
            bufferIndex += 8 + 4 * this.ownerGroupSid.sub_authority_count;
        }

        bufferIndex = start + daclOffset;

        if (daclOffset > 0) {
            bufferIndex++; // revision
            bufferIndex++;
            SMBUtil.readInt2(buffer, bufferIndex);
            bufferIndex += 2;
            final int numAces = SMBUtil.readInt4(buffer, bufferIndex);
            bufferIndex += 4;

            if (numAces > 4096) {
                throw new SMBProtocolDecodingException("Invalid SecurityDescriptor");
            }

            this.aces = new ACE[numAces];
            for (int i = 0; i < numAces; i++) {
                this.aces[i] = new ACE();
                bufferIndex += this.aces[i].decode(buffer, bufferIndex, len - bufferIndex);
            }
        } else {
            this.aces = null;
        }

        return bufferIndex - start;
    }

    @Override
    public String toString() {
        StringBuilder ret = new StringBuilder("SecurityDescriptor:\n");
        if (this.aces != null) {
            for (final ACE element : this.aces) {
                ret.append(element.toString()).append("\n");
            }
        } else {
            ret.append("NULL");
        }
        return ret.toString();
    }
}
