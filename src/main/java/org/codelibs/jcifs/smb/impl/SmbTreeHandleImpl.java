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
package org.codelibs.jcifs.smb.impl;

import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.RuntimeCIFSException;
import org.codelibs.jcifs.smb.SmbTreeHandle;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlockResponse;
import org.codelibs.jcifs.smb.internal.SmbNegotiationResponse;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComNegotiateResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author mbechler
 *
 */
class SmbTreeHandleImpl implements SmbTreeHandleInternal {

    private static final Logger log = LoggerFactory.getLogger(SmbTreeHandleImpl.class);

    private final SmbResourceLocatorImpl resourceLoc;
    private final SmbTreeConnection treeConnection;

    private final AtomicLong usageCount = new AtomicLong(1);

    /**
     * @param resourceLoc
     * @param treeConnection
     */
    public SmbTreeHandleImpl(final SmbResourceLocatorImpl resourceLoc, final SmbTreeConnection treeConnection) {
        this.resourceLoc = resourceLoc;
        this.treeConnection = treeConnection.acquire();
    }

    @Override
    public SmbSessionImpl getSession() {
        return this.treeConnection.getSession();
    }

    @Override
    public void ensureDFSResolved() throws CIFSException {
        this.treeConnection.ensureDFSResolved(this.resourceLoc);
    }

    @Override
    public boolean hasCapability(final int cap) throws SmbException {
        return this.treeConnection.hasCapability(cap);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbTreeHandle#isConnected()
     */
    @Override
    public boolean isConnected() {
        return this.treeConnection.isConnected();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbTreeHandle#getConfig()
     */
    @Override
    public Configuration getConfig() {
        return this.treeConnection.getConfig();
    }

    /**
     * @return the currently connected tree id
     */
    public long getTreeId() {
        return this.treeConnection.getTreeId();
    }

    /**
     *
     * @param req
     * @param params
     * @return response
     * @throws CIFSException
     */
    public <T extends CommonServerMessageBlockResponse> T send(final org.codelibs.jcifs.smb.internal.Request<T> req,
            final RequestParam... params) throws CIFSException {
        return send(req, null, params);
    }

    /**
     * @param request
     * @param response
     * @param params
     * @return response
     * @throws CIFSException
     */
    public <T extends CommonServerMessageBlockResponse> T send(final CommonServerMessageBlockRequest request, final T response,
            final RequestParam... params) throws CIFSException {
        return this.treeConnection.send(this.resourceLoc, request, response, params);
    }

    /**
     *
     * @param request
     * @param response
     * @param params
     * @return response
     * @throws CIFSException
     */
    public <T extends CommonServerMessageBlockResponse> T send(final CommonServerMessageBlockRequest request, final T response,
            final Set<RequestParam> params) throws CIFSException {
        return this.treeConnection.send(this.resourceLoc, request, response, params);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbTreeHandle#close()
     */
    @Override
    public synchronized void close() {
        release();
    }

    /**
     * @return tree handle with increased usage count
     */
    public SmbTreeHandleImpl acquire() {
        if (this.usageCount.incrementAndGet() == 1) {
            this.treeConnection.acquire();
        }
        return this;
    }

    @Override
    public void release() {
        final long us = this.usageCount.decrementAndGet();
        if (us == 0) {
            this.treeConnection.release();
        } else if (us < 0) {
            throw new RuntimeCIFSException("Usage count dropped below zero");
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#finalize()
     */
    @Override
    protected void finalize() throws Throwable {
        if (this.usageCount.get() != 0) {
            log.warn("Tree handle was not properly released " + this.resourceLoc.getURL());
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbTreeHandle#getRemoteHostName()
     */
    @Override
    public String getRemoteHostName() {
        try (SmbSessionImpl session = this.treeConnection.getSession(); SmbTransportImpl transport = session.getTransport()) {
            return transport.getRemoteHostName();
        }
    }

    /**
     * {@inheritDoc}
     *
     * @throws SmbException
     *
     * @see org.codelibs.jcifs.smb.SmbTreeHandle#getServerTimeZoneOffset()
     */
    @Override
    public long getServerTimeZoneOffset() throws SmbException {
        try (SmbSessionImpl session = this.treeConnection.getSession(); SmbTransportImpl transport = session.getTransport()) {
            final SmbNegotiationResponse nego = transport.getNegotiateResponse();
            if (nego instanceof SmbComNegotiateResponse) {
                return ((SmbComNegotiateResponse) nego).getServerData().serverTimeZone * 1000 * 60L;
            }
            return 0;
        }
    }

    /**
     * {@inheritDoc}
     *
     * @throws SmbException
     *
     * @see org.codelibs.jcifs.smb.SmbTreeHandle#getOEMDomainName()
     */
    @Override
    public String getOEMDomainName() throws SmbException {
        try (SmbSessionImpl session = this.treeConnection.getSession(); SmbTransportImpl transport = session.getTransport()) {
            final SmbNegotiationResponse nego = transport.getNegotiateResponse();
            if (nego instanceof SmbComNegotiateResponse) {
                return ((SmbComNegotiateResponse) nego).getServerData().oemDomainName;
            }
            return null;
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbTreeHandle#getTreeType()
     */
    @Override
    public int getTreeType() {
        return this.treeConnection.getTreeType();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbTreeHandle#getConnectedShare()
     */
    @Override
    public String getConnectedShare() {
        return this.treeConnection.getConnectedShare();
    }

    /**
     *
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbTreeHandle#isSameTree(org.codelibs.jcifs.smb.SmbTreeHandle)
     */
    @Override
    public boolean isSameTree(final SmbTreeHandle th) {
        if (!(th instanceof SmbTreeHandleImpl)) {
            return false;
        }
        return this.treeConnection.isSame(((SmbTreeHandleImpl) th).treeConnection);
    }

    @Override
    public int getSendBufferSize() throws SmbException {
        try (SmbSessionImpl session = this.treeConnection.getSession(); SmbTransportImpl transport = session.getTransport()) {
            return transport.getNegotiateResponse().getSendBufferSize();
        }
    }

    @Override
    public int getReceiveBufferSize() throws SmbException {
        try (SmbSessionImpl session = this.treeConnection.getSession(); SmbTransportImpl transport = session.getTransport()) {
            return transport.getNegotiateResponse().getReceiveBufferSize();
        }
    }

    @Override
    public int getMaximumBufferSize() throws SmbException {
        try (SmbSessionImpl session = this.treeConnection.getSession(); SmbTransportImpl transport = session.getTransport()) {
            return transport.getNegotiateResponse().getTransactionBufferSize();
        }
    }

    @Override
    public boolean areSignaturesActive() throws SmbException {
        try (SmbSessionImpl session = this.treeConnection.getSession(); SmbTransportImpl transport = session.getTransport()) {
            return transport.getNegotiateResponse().isSigningNegotiated();
        }
    }

    /**
     * @return whether this tree handle uses SMB2
     */
    @Override
    public boolean isSMB2() {
        try (SmbSessionImpl session = this.treeConnection.getSession(); SmbTransportImpl transport = session.getTransport()) {
            return transport.isSMB2();
        } catch (final SmbException e) {
            log.debug("Failed to connect for determining SMB2 support", e);
            return false;
        }
    }

}
