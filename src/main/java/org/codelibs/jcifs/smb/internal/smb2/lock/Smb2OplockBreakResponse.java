/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.codelibs.jcifs.smb.internal.smb2.lock;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Response;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2 Oplock Break Response, MS-SMB2 2.2.25.1.
 *
 * <p>
 * The server's reply to an oplock break acknowledgement, naming the level the open is left at. A non-zero status
 * means the acknowledgement was refused, in which case the client keeps no oplock at all (MS-SMB2 3.2.5.19.3).
 * </p>
 */
public class Smb2OplockBreakResponse extends ServerMessageBlock2Response {

    private static final int STRUCTURE_SIZE = 24;

    private byte oplockLevel;
    private byte[] fileId;

    /**
     * Constructs an oplock break response with the given configuration.
     *
     * @param config the configuration for this response
     */
    public Smb2OplockBreakResponse(final Configuration config) {
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
    protected int readBytesWireFormat(final byte[] buffer, final int bufferIndex) throws SMBProtocolDecodingException {
        final int structureSize = SMBUtil.readInt2(buffer, bufferIndex);
        if (structureSize != STRUCTURE_SIZE) {
            throw new SMBProtocolDecodingException("Expected structureSize = 24");
        }
        this.oplockLevel = buffer[bufferIndex + 2];
        this.fileId = new byte[16];
        System.arraycopy(buffer, bufferIndex + 8, this.fileId, 0, 16);
        return STRUCTURE_SIZE;
    }

    /**
     * @return the oplock level the open is left at
     */
    public byte getOplockLevel() {
        return this.oplockLevel;
    }

    /**
     * @return the file id of the open, 16 bytes
     */
    public byte[] getFileId() {
        return this.fileId;
    }
}
