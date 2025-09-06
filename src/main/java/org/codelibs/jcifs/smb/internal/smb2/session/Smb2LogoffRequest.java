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
package org.codelibs.jcifs.smb.internal.smb2.session;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Request;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2 Logoff request message. This command is used to terminate an SMB2 session.
 *
 * @author mbechler
 *
 */
public class Smb2LogoffRequest extends ServerMessageBlock2Request<Smb2LogoffResponse> {

    /**
     * Constructs an SMB2 logoff request with the given configuration.
     *
     * @param config the configuration for this request
     */
    public Smb2LogoffRequest(final Configuration config) {
        super(config, SMB2_LOGOFF);
    }

    @Override
    protected Smb2LogoffResponse createResponse(final CIFSContext tc, final ServerMessageBlock2Request<Smb2LogoffResponse> req) {
        return new Smb2LogoffResponse(tc.getConfig());
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest#size()
     */
    @Override
    public int size() {
        return size8(Smb2Constants.SMB2_HEADER_LENGTH + 4);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat(final byte[] dst, final int dstIndex) {
        SMBUtil.writeInt2(4, dst, dstIndex);
        SMBUtil.writeInt2(0, dst, dstIndex + 2);
        return 4;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat(final byte[] buffer, final int bufferIndex) {
        return 0;
    }

}
