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

/**
 * SMB2 Lock response message. This response acknowledges the successful
 * acquisition or release of byte-range locks.
 *
 * @author mbechler
 *
 */
public class Smb2LockResponse extends ServerMessageBlock2Response {

    /**
     * Constructs an SMB2 lock response with the given configuration.
     *
     * @param config the configuration for this response
     */
    public Smb2LockResponse(final Configuration config) {
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
        if (structureSize != 4) {
            throw new SMBProtocolDecodingException("Expected structureSize = 4");
        }
        return 4;
    }

}
