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

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlockResponse;
import org.codelibs.jcifs.smb.internal.Request;

/**
 * Base class for SMB2/SMB3 request messages.
 *
 * This abstract class provides common functionality for handling
 * request messages in the SMB2/SMB3 protocol.
 *
 * @author mbechler
 * @param <T>
 *            response type
 */
public abstract class ServerMessageBlock2Request<T extends ServerMessageBlock2Response> extends ServerMessageBlock2
        implements CommonServerMessageBlockRequest, Request<T> {

    private T response;
    private Integer overrideTimeout;

    /**
     * Constructor for SMB2 request with configuration.
     *
     * @param config the configuration object
     */
    protected ServerMessageBlock2Request(final Configuration config) {
        super(config);
    }

    /**
     * Constructor for SMB2 request with configuration and command.
     *
     * @param config the configuration object
     * @param command the SMB2 command code
     */
    public ServerMessageBlock2Request(final Configuration config, final int command) {
        super(config, command);
    }

    @Override
    public ServerMessageBlock2Request<T> ignoreDisconnect() {
        return this;
    }

    @Override
    public ServerMessageBlock2Request<?> getNext() {
        return (ServerMessageBlock2Request<?>) super.getNext();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.util.transport.Request#isCancel()
     */
    @Override
    public boolean isCancel() {
        return false;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest#isResponseAsync()
     */
    @Override
    public boolean isResponseAsync() {
        return getAsyncId() != 0;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest#allowChain(org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest)
     */
    @Override
    public boolean allowChain(final CommonServerMessageBlockRequest next) {
        return getConfig().isAllowCompound(getClass().getSimpleName()) && getConfig().isAllowCompound(next.getClass().getSimpleName());
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest#createCancel()
     */
    @Override
    public CommonServerMessageBlockRequest createCancel() {
        return new Smb2CancelRequest(getConfig(), getMid(), getAsyncId());
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest#split()
     */
    @Override
    public CommonServerMessageBlockRequest split() {
        final ServerMessageBlock2Request<?> n = getNext();
        if (n != null) {
            setNext(null);
            n.clearFlags(SMB2_FLAGS_RELATED_OPERATIONS);
        }
        return n;
    }

    /**
     * Sets the next request in the compound chain.
     *
     * @param next the next request
     */
    public void setNext(final ServerMessageBlock2Request<?> next) {
        super.setNext(next);
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
     * @see org.codelibs.jcifs.smb.util.transport.Request#setRequestCredits(int)
     */
    @Override
    public void setRequestCredits(final int credits) {
        setCredit(credits);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest#getOverrideTimeout()
     */
    @Override
    public final Integer getOverrideTimeout() {
        return this.overrideTimeout;
    }

    /**
     * Sets an override timeout for this request.
     *
     * @param overrideTimeout
     *            the overrideTimeout to set
     */
    public final void setOverrideTimeout(final Integer overrideTimeout) {
        this.overrideTimeout = overrideTimeout;
    }

    /**
     *
     * @return create response
     */
    @Override
    public T initResponse(final CIFSContext tc) {
        final T resp = createResponse(tc, this);
        if (resp == null) {
            return null;
        }
        resp.setDigest(getDigest());
        setResponse(resp);

        final ServerMessageBlock2 n = getNext();
        if (n instanceof ServerMessageBlock2Request<?>) {
            resp.setNext(((ServerMessageBlock2Request<?>) n).initResponse(tc));
        }
        return resp;
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
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#encode(byte[], int)
     */
    @Override
    public int encode(final byte[] dst, final int dstIndex) {
        final int len = super.encode(dst, dstIndex);
        final int exp = size();
        final int actual = getLength();
        if (exp != actual) {
            throw new IllegalStateException(String.format("Wrong size calculation have %d expect %d", exp, actual));
        }
        return len;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#getResponse()
     */
    @Override
    public T getResponse() {
        return this.response;
    }

    /**
     * Create the response object for this request
     *
     * @param tc the CIFS context
     * @param req the request object
     * @return the response object
     */
    protected abstract T createResponse(CIFSContext tc, ServerMessageBlock2Request<T> req);

    /**
     *
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#setResponse(org.codelibs.jcifs.smb.internal.CommonServerMessageBlockResponse)
     */
    @SuppressWarnings("unchecked")
    @Override
    public final void setResponse(final CommonServerMessageBlockResponse msg) {
        if (msg != null && !(msg instanceof ServerMessageBlock2)) {
            throw new IllegalArgumentException("Incompatible response");
        }
        this.response = (T) msg;
    }
}
