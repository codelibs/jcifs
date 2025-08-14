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
package jcifs.internal.smb2.tree;

import java.nio.charset.StandardCharsets;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.smb2.ServerMessageBlock2;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;

/**
 * SMB2 Tree Connect request message.
 *
 * This command is used to connect to a shared resource
 * on the server, such as a file share or printer.
 *
 * @author mbechler
 */
public class Smb2TreeConnectRequest extends ServerMessageBlock2Request<Smb2TreeConnectResponse> {

    private int treeFlags;
    private final String path;

    /**
     * @param config
     * @param path
     */
    public Smb2TreeConnectRequest(final Configuration config, final String path) {
        super(config, SMB2_TREE_CONNECT);
        this.path = path;
    }

    @Override
    protected Smb2TreeConnectResponse createResponse(final CIFSContext tc, final ServerMessageBlock2Request<Smb2TreeConnectResponse> req) {
        return new Smb2TreeConnectResponse(tc.getConfig());
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#chain(jcifs.internal.smb2.ServerMessageBlock2)
     */
    @Override
    public boolean chain(final ServerMessageBlock2 n) {
        n.setTreeId(Smb2Constants.UNSPECIFIED_TREEID);
        return super.chain(n);
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#size()
     */
    @Override
    public int size() {
        return size8(Smb2Constants.SMB2_HEADER_LENGTH + 8 + this.path.length() * 2);
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        SMBUtil.writeInt2(9, dst, dstIndex);
        SMBUtil.writeInt2(this.treeFlags, dst, dstIndex + 2);
        dstIndex += 4;

        final byte[] data = this.path.getBytes(StandardCharsets.UTF_16LE);
        final int offsetOffset = dstIndex;
        SMBUtil.writeInt2(data.length, dst, dstIndex + 2);
        dstIndex += 4;
        SMBUtil.writeInt2(dstIndex - getHeaderStart(), dst, offsetOffset);

        System.arraycopy(data, 0, dst, dstIndex, data.length);
        dstIndex += data.length;
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
