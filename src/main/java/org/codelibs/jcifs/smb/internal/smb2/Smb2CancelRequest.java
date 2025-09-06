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
package org.codelibs.jcifs.smb.internal.smb2;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2 Cancel request message.
 *
 * This command is used to cancel a previously sent command
 * that is still being processed by the server.
 *
 * @author mbechler
 */
public class Smb2CancelRequest extends ServerMessageBlock2 implements CommonServerMessageBlockRequest {

    /**
     * Constructs a SMB2 cancel request
     *
     * @param config
     *            The configuration to use
     * @param mid
     *            The message ID of the request to cancel
     * @param asyncId
     *            The async ID for asynchronous operations (0 for synchronous)
     */
    public Smb2CancelRequest(final Configuration config, final long mid, final long asyncId) {
        super(config, SMB2_CANCEL);
        setMid(mid);
        setAsyncId(asyncId);
        if (asyncId != 0) {
            addFlags(SMB2_FLAGS_ASYNC_COMMAND);
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.util.transport.Request#getCreditCost()
     */
    @Override
    public int getCreditCost() {
        return 1;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest#isResponseAsync()
     */
    @Override
    public boolean isResponseAsync() {
        return false;
    }

    @Override
    public ServerMessageBlock2Request<?> getNext() {
        return null;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest#getOverrideTimeout()
     */
    @Override
    public Integer getOverrideTimeout() {
        return null;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest#allowChain(org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest)
     */
    @Override
    public boolean allowChain(final CommonServerMessageBlockRequest next) {
        return false;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest#split()
     */
    @Override
    public CommonServerMessageBlockRequest split() {
        return null;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest#createCancel()
     */
    @Override
    public CommonServerMessageBlockRequest createCancel() {
        return null;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.util.transport.Request#setRequestCredits(int)
     */
    @Override
    public void setRequestCredits(final int credits) {
        setCredit(credits);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest#setTid(int)
     */
    @Override
    public void setTid(final int t) {
        setTreeId(t);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.util.transport.Request#isCancel()
     */
    @Override
    public boolean isCancel() {
        return true;
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
    protected int writeBytesWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        SMBUtil.writeInt2(4, dst, dstIndex);
        dstIndex += 4;
        return dstIndex - start;
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
