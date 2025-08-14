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
package jcifs.internal.smb2;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.util.SMBUtil;

/**
 * SMB2 Echo request message.
 *
 * This command is used to test connectivity and ensure the
 * SMB2 connection is still active.
 *
 * @author mbechler
 */
public class Smb2EchoRequest extends ServerMessageBlock2Request<Smb2EchoResponse> {

    /**
     * @param config
     */
    public Smb2EchoRequest(final Configuration config) {
        super(config, SMB2_ECHO);
    }

    @Override
    protected Smb2EchoResponse createResponse(final CIFSContext tc, final ServerMessageBlock2Request<Smb2EchoResponse> req) {
        return new Smb2EchoResponse(tc.getConfig());
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#size()
     */
    @Override
    public int size() {
        return size8(Smb2Constants.SMB2_HEADER_LENGTH + 4);
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        SMBUtil.writeInt2(4, dst, dstIndex);
        dstIndex += 4;
        return dstIndex - start;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat(final byte[] buffer, final int bufferIndex) {
        return 0;
    }

}
