/*
 * © 2017 AgNO3 Gmbh & Co. KG
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
package org.codelibs.jcifs.smb.internal.smb2.lock;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Response;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.codelibs.jcifs.smb.util.Hexdump;

/**
 * SMB2 Oplock Break notification message. This server-initiated message notifies the client
 * that an opportunistic lock must be broken due to conflicting access from another client.
 *
 * @author mbechler
 *
 */
public class Smb2OplockBreakNotification extends ServerMessageBlock2Response {

    private byte oplockLevel;
    private byte[] fileId;

    /**
     * Constructs an SMB2 oplock break notification with the given configuration.
     *
     * @param config the configuration for this notification
     */
    public Smb2OplockBreakNotification(final Configuration config) {
        super(config);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat(final byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException {
        final int start = bufferIndex;
        final int structureSize = SMBUtil.readInt2(buffer, bufferIndex);
        if (structureSize != 24) {
            throw new SMBProtocolDecodingException("Expected structureSize = 24");
        }

        this.oplockLevel = buffer[bufferIndex + 2];
        bufferIndex += 4;
        bufferIndex += 4; // Reserved2

        this.fileId = new byte[16];
        System.arraycopy(buffer, bufferIndex, this.fileId, 0, 16);
        bufferIndex += 16;

        return bufferIndex - start;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#toString()
     */
    @Override
    public String toString() {
        return "Smb2OpblockBreakNotification[oplockLevel=" + this.oplockLevel + ",fileId=" + Hexdump.toHexString(this.fileId) + "]";
    }
}
