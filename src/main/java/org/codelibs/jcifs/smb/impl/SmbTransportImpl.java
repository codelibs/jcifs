/* org.codelibs.jcifs.smb smb client library in Java
 * Copyright (C) 2005  "Michael B. Allen" <jcifs at samba dot org>
 *                  "Eric Glass" <jcifs at samba dot org>
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

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.codelibs.jcifs.smb.Address;
import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.DfsReferralData;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.SmbTransport;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlock;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlockResponse;
import org.codelibs.jcifs.smb.internal.RequestWithPath;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.SMBSigningDigest;
import org.codelibs.jcifs.smb.internal.SmbNegotiation;
import org.codelibs.jcifs.smb.internal.SmbNegotiationResponse;
import org.codelibs.jcifs.smb.internal.dfs.DfsReferralDataImpl;
import org.codelibs.jcifs.smb.internal.dfs.DfsReferralRequestBuffer;
import org.codelibs.jcifs.smb.internal.dfs.DfsReferralResponseBuffer;
import org.codelibs.jcifs.smb.internal.dfs.Referral;
import org.codelibs.jcifs.smb.internal.smb1.AndXServerMessageBlock;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComBlankResponse;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComLockingAndX;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComNegotiate;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComNegotiateResponse;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComReadAndXResponse;
import org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransaction;
import org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransactionResponse;
import org.codelibs.jcifs.smb.internal.smb1.trans2.Trans2GetDfsReferral;
import org.codelibs.jcifs.smb.internal.smb1.trans2.Trans2GetDfsReferralResponse;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Request;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Response;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.codelibs.jcifs.smb.internal.smb2.Smb2EncryptionContext;
import org.codelibs.jcifs.smb.internal.smb2.Smb3KeyDerivation;
import org.codelibs.jcifs.smb.internal.smb2.io.Smb2ReadResponse;
import org.codelibs.jcifs.smb.internal.smb2.ioctl.Smb2IoctlRequest;
import org.codelibs.jcifs.smb.internal.smb2.ioctl.Smb2IoctlResponse;
import org.codelibs.jcifs.smb.internal.smb2.lock.Smb2OplockBreakNotification;
import org.codelibs.jcifs.smb.internal.smb2.nego.EncryptionNegotiateContext;
import org.codelibs.jcifs.smb.internal.smb2.nego.Smb2NegotiateRequest;
import org.codelibs.jcifs.smb.internal.smb2.nego.Smb2NegotiateResponse;
import org.codelibs.jcifs.smb.netbios.Name;
import org.codelibs.jcifs.smb.netbios.NbtException;
import org.codelibs.jcifs.smb.netbios.SessionRequestPacket;
import org.codelibs.jcifs.smb.netbios.SessionServicePacket;
import org.codelibs.jcifs.smb.util.Crypto;
import org.codelibs.jcifs.smb.util.Encdec;
import org.codelibs.jcifs.smb.util.Hexdump;
import org.codelibs.jcifs.smb.util.transport.Request;
import org.codelibs.jcifs.smb.util.transport.Response;
import org.codelibs.jcifs.smb.util.transport.Transport;
import org.codelibs.jcifs.smb.util.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 */
class SmbTransportImpl extends Transport implements SmbTransportInternal, SmbConstants {

    private static Logger log = LoggerFactory.getLogger(SmbTransportImpl.class);

    private boolean smb2 = false;
    private final InetAddress localAddr;
    private final int localPort;
    private final Address address;
    private Socket socket;
    private int port;
    private final AtomicLong mid = new AtomicLong();
    private OutputStream out;
    private InputStream in;
    private final byte[] sbuf = new byte[1024]; /* small local buffer */
    private long sessionExpiration;
    private final List<SmbSessionImpl> sessions = new LinkedList<>();

    private String tconHostName = null;

    private final CIFSContext transportContext;
    private final boolean signingEnforced;

    private SmbNegotiationResponse negotiated;

    private SMBSigningDigest digest;

    private final Semaphore credits = new Semaphore(1, true);

    private final int desiredCredits = 512;

    private byte[] preauthIntegrityHash = new byte[64];

    SmbTransportImpl(final CIFSContext tc, final Address address, final int port, final InetAddress localAddr, final int localPort,
            final boolean forceSigning) {
        this.transportContext = tc;

        this.signingEnforced = forceSigning || this.getContext().getConfig().isSigningEnforced();
        this.sessionExpiration = System.currentTimeMillis() + tc.getConfig().getSessionTimeout();

        this.address = address;
        this.port = port;
        this.localAddr = localAddr;
        this.localPort = localPort;

    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.util.transport.Transport#getResponseTimeout()
     */
    @Override
    protected int getResponseTimeout(final Request req) {
        if (req instanceof CommonServerMessageBlockRequest) {
            final Integer overrideTimeout = ((CommonServerMessageBlockRequest) req).getOverrideTimeout();
            if (overrideTimeout != null) {
                return overrideTimeout;
            }
        }
        return getContext().getConfig().getResponseTimeout();
    }

    @Override
    public Address getRemoteAddress() {
        return this.address;
    }

    @Override
    public String getRemoteHostName() {
        return this.tconHostName;
    }

    /**
     *
     * @return number of sessions on this transport
     */
    public int getNumSessions() {
        return this.sessions.size();
    }

    @Override
    public int getInflightRequests() {
        return this.response_map.size();
    }

    @Override
    public boolean isDisconnected() {
        final Socket s = this.socket;
        return super.isDisconnected() || s == null || s.isClosed();
    }

    @Override
    public boolean isFailed() {
        final Socket s = this.socket;
        return super.isFailed() || s == null || s.isClosed();
    }

    @Override
    public boolean hasCapability(final int cap) throws SmbException {
        return getNegotiateResponse().haveCapabilitiy(cap);
    }

    /**
     * @return the negotiated
     * @throws SmbException
     */
    SmbNegotiationResponse getNegotiateResponse() throws SmbException {
        try {
            if (this.negotiated == null) {
                connect(this.transportContext.getConfig().getResponseTimeout());
            }
        } catch (final IOException ioe) {
            throw new SmbException(ioe.getMessage(), ioe);
        }
        final SmbNegotiationResponse r = this.negotiated;
        if (r == null) {
            throw new SmbException("Connection did not complete, failed to get negotiation response");
        }
        return r;
    }

    /**
     * @return whether this is SMB2 transport
     * @throws SmbException
     */
    @Override
    public boolean isSMB2() throws SmbException {
        return this.smb2 || getNegotiateResponse() instanceof Smb2NegotiateResponse;
    }

    /**
     * @param digest
     */
    public void setDigest(final SMBSigningDigest digest) {
        this.digest = digest;
    }

    /**
     * @return the digest
     */
    public SMBSigningDigest getDigest() {
        return this.digest;
    }

    /**
     * @return the context associated with this transport connection
     */
    @Override
    public CIFSContext getContext() {
        return this.transportContext;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.util.transport.Transport#acquire()
     */
    @Override
    public SmbTransportImpl acquire() {
        return (SmbTransportImpl) super.acquire();
    }

    /**
     * @return the server's encryption key
     */
    @Override
    public byte[] getServerEncryptionKey() {
        if (this.negotiated == null) {
            return null;
        }

        if (this.negotiated instanceof SmbComNegotiateResponse) {
            return ((SmbComNegotiateResponse) this.negotiated).getServerData().encryptionKey;
        }
        return null;
    }

    @Override
    public boolean isSigningOptional() throws SmbException {
        if (this.signingEnforced) {
            return false;
        }
        final SmbNegotiationResponse nego = getNegotiateResponse();
        return nego.isSigningNegotiated() && !nego.isSigningRequired();
    }

    @Override
    public boolean isSigningEnforced() throws SmbException {
        if (this.signingEnforced) {
            return true;
        }
        return getNegotiateResponse().isSigningRequired();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbTransport#unwrap(java.lang.Class)
     */
    @SuppressWarnings("unchecked")
    @Override
    public <T extends SmbTransport> T unwrap(final Class<T> type) {
        if (type.isAssignableFrom(this.getClass())) {
            return (T) this;
        }
        throw new ClassCastException();
    }

    /**
     *
     * @param tf
     * @return a session for the context
     */
    @Override
    public SmbSessionImpl getSmbSession(final CIFSContext tf) {
        return getSmbSession(tf, null, null);
    }

    /**
     *
     * @param tf
     *            context to use
     * @return a session for the context
     */
    @Override
    @SuppressWarnings("resource")
    public synchronized SmbSessionImpl getSmbSession(final CIFSContext tf, String targetHost, String targetDomain) {
        long now;

        if (log.isTraceEnabled()) {
            log.trace("Currently " + this.sessions.size() + " session(s) active for " + this);
        }

        if (targetHost != null) {
            targetHost = targetHost.toLowerCase(Locale.ROOT);
        }

        if (targetDomain != null) {
            targetDomain = targetDomain.toUpperCase(Locale.ROOT);
        }

        ListIterator<SmbSessionImpl> iter = this.sessions.listIterator();
        while (iter.hasNext()) {
            final SmbSessionImpl ssn = iter.next();
            if (ssn.matches(tf, targetHost, targetDomain)) {
                if (log.isTraceEnabled()) {
                    log.trace("Reusing existing session " + ssn);
                }
                return ssn.acquire();
            }
            if (log.isTraceEnabled()) {
                log.trace("Existing session " + ssn + " does not match " + tf.getCredentials());
            }
        }

        /* logoff old sessions */
        if (tf.getConfig().getSessionTimeout() > 0 && this.sessionExpiration < (now = System.currentTimeMillis())) {
            this.sessionExpiration = now + tf.getConfig().getSessionTimeout();
            iter = this.sessions.listIterator();
            while (iter.hasNext()) {
                final SmbSessionImpl ssn = iter.next();
                if (ssn.getExpiration() != null && ssn.getExpiration() < now && !ssn.isInUse()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Closing session after timeout " + ssn);
                    }
                    ssn.logoff(false, false);
                }
            }
        }
        final SmbSessionImpl ssn = new SmbSessionImpl(tf, targetHost, targetDomain, this);
        if (log.isDebugEnabled()) {
            log.debug("Establishing new session " + ssn + " on " + this.name);
        }
        this.sessions.add(ssn);
        return ssn;
    }

    boolean matches(final Address addr, final int prt, final InetAddress laddr, final int lprt, String hostName) {
        if (this.state == 5 || this.state == 6) {
            // don't reuse disconnecting/disconnected transports
            return false;
        }
        if (hostName == null) {
            hostName = addr.getHostName();
        }
        return (this.tconHostName == null || hostName.equalsIgnoreCase(this.tconHostName)) && addr.equals(this.address)
                && (prt == 0 || prt == this.port ||
                /* port 139 is ok if 445 was requested */
                        prt == 445 && this.port == 139)
                && (laddr == this.localAddr || laddr != null && laddr.equals(this.localAddr)) && lprt == this.localPort;
    }

    void ssn139() throws IOException {
        final CIFSContext tc = this.transportContext;
        final Name calledName = new Name(tc.getConfig(), this.address.firstCalledName(), 0x20, null);
        do {
            this.socket = new Socket();
            if (this.localAddr != null) {
                this.socket.bind(new InetSocketAddress(this.localAddr, this.localPort));
            }
            this.socket.connect(new InetSocketAddress(this.address.getHostAddress(), 139), tc.getConfig().getConnTimeout());
            this.socket.setSoTimeout(tc.getConfig().getSoTimeout());

            this.out = this.socket.getOutputStream();
            this.in = this.socket.getInputStream();

            final SessionServicePacket ssp = new SessionRequestPacket(tc.getConfig(), calledName, tc.getNameServiceClient().getLocalName());
            this.out.write(this.sbuf, 0, ssp.writeWireFormat(this.sbuf, 0));
            if (readn(this.in, this.sbuf, 0, 4) < 4) {
                try {
                    this.socket.close();
                } catch (final IOException ioe) {
                    log.debug("Failed to close socket", ioe);
                }
                throw new SmbException("EOF during NetBIOS session request");
            }
            switch (this.sbuf[0] & 0xFF) {
            case SessionServicePacket.POSITIVE_SESSION_RESPONSE:
                if (log.isDebugEnabled()) {
                    log.debug("session established ok with " + this.address);
                }
                return;
            case SessionServicePacket.NEGATIVE_SESSION_RESPONSE:
                final int errorCode = this.in.read() & 0xFF;
                switch (errorCode) {
                case NbtException.CALLED_NOT_PRESENT:
                case NbtException.NOT_LISTENING_CALLED:
                    this.socket.close();
                    break;
                default:
                    disconnect(true);
                    throw new NbtException(NbtException.ERR_SSN_SRVC, errorCode);
                }
                break;
            case -1:
                disconnect(true);
                throw new NbtException(NbtException.ERR_SSN_SRVC, NbtException.CONNECTION_REFUSED);
            default:
                disconnect(true);
                throw new NbtException(NbtException.ERR_SSN_SRVC, 0);
            }
        } while ((calledName.name = this.address.nextCalledName(tc)) != null);

        throw new IOException("Failed to establish session with " + this.address);
    }

    private SmbNegotiation negotiate(int prt) throws IOException {
        /*
         * We cannot use Transport.sendrecv() yet because
         * the Transport thread is not setup until doConnect()
         * returns and we want to suppress all communication
         * until we have properly negotiated.
         */
        synchronized (this.inLock) {
            if (prt == 139) {
                ssn139();
            } else {
                if (prt == 0) {
                    prt = DEFAULT_PORT; // 445
                }

                this.socket = new Socket();
                if (this.localAddr != null) {
                    this.socket.bind(new InetSocketAddress(this.localAddr, this.localPort));
                }
                this.socket.connect(new InetSocketAddress(this.address.getHostAddress(), prt),
                        this.transportContext.getConfig().getConnTimeout());
                this.socket.setSoTimeout(this.transportContext.getConfig().getSoTimeout());

                this.out = this.socket.getOutputStream();
                this.in = this.socket.getInputStream();
            }

            if (this.credits.drainPermits() == 0) {
                log.debug("It appears we previously lost some credits");
            }

            if (this.smb2 || this.getContext().getConfig().isUseSMB2OnlyNegotiation()) {
                log.debug("Using SMB2 only negotiation");
                return negotiate2(null);
            }

            final SmbComNegotiate comNeg = new SmbComNegotiate(getContext().getConfig(), this.signingEnforced);
            final int n = negotiateWrite(comNeg, true);
            negotiatePeek();

            if (this.smb2) {
                final Smb2NegotiateResponse r = new Smb2NegotiateResponse(getContext().getConfig());
                r.decode(this.sbuf, 4);
                r.received();

                if (r.getDialectRevision() == Smb2Constants.SMB2_DIALECT_ANY) {
                    return negotiate2(r);
                } else if (r.getDialectRevision() != Smb2Constants.SMB2_DIALECT_0202) {
                    throw new CIFSException("Server returned invalid dialect verison in multi protocol negotiation");
                }

                final int permits = r.getInitialCredits();
                if (permits > 0) {
                    this.credits.release(permits);
                }
                Arrays.fill(this.sbuf, (byte) 0);
                return new SmbNegotiation(new Smb2NegotiateRequest(getContext().getConfig(),
                        this.signingEnforced ? Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED
                                : Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED),
                        r, null, null);
            }
            if (this.getContext().getConfig().getMinimumVersion().isSMB2()) {
                throw new CIFSException("Server does not support SMB2");
            }
            SmbNegotiationResponse resp = new SmbComNegotiateResponse(getContext());
            resp.decode(this.sbuf, 4);
            resp.received();

            if (log.isTraceEnabled()) {
                log.trace(resp.toString());
                log.trace(Hexdump.toHexString(this.sbuf, 4, n));
            }

            final int permits = resp.getInitialCredits();
            if (permits > 0) {
                this.credits.release(permits);
            }
            Arrays.fill(this.sbuf, (byte) 0);
            return new SmbNegotiation(comNeg, resp, null, null);
        }
    }

    /**
     * @return
     * @throws IOException
     */
    private int negotiateWrite(final CommonServerMessageBlockRequest req, final boolean setmid) throws IOException {
        if (setmid) {
            makeKey(req);
        } else {
            req.setMid(0);
            this.mid.set(1);
        }
        final int n = req.encode(this.sbuf, 4);
        Encdec.enc_uint32be(n & 0xFFFF, this.sbuf, 0); /* 4 byte ssn msg header */

        if (log.isTraceEnabled()) {
            log.trace(req.toString());
            log.trace(Hexdump.toHexString(this.sbuf, 4, n));
        }

        this.out.write(this.sbuf, 0, 4 + n);
        this.out.flush();
        log.trace("Wrote negotiate request");
        return n;
    }

    /**
     * @throws SocketException
     * @throws IOException
     */
    private void negotiatePeek() throws SocketException, IOException {
        /*
         * Note the Transport thread isn't running yet so we can
         * read from the socket here.
         */
        try {
            this.socket.setSoTimeout(this.transportContext.getConfig().getConnTimeout());
            if (peekKey() == null) { /* try to read header */
                throw new IOException("transport closed in negotiate");
            }
        } finally {
            this.socket.setSoTimeout(this.transportContext.getConfig().getSoTimeout());
        }
        final int size = Encdec.dec_uint16be(this.sbuf, 2) & 0xFFFF;
        if (size < 33 || 4 + size > this.sbuf.length) {
            throw new IOException("Invalid payload size: " + size);
        }
        final int hdrSize = this.smb2 ? Smb2Constants.SMB2_HEADER_LENGTH : SMB1_HEADER_LENGTH;
        readn(this.in, this.sbuf, 4 + hdrSize, size - hdrSize);
        log.trace("Read negotiate response");
    }

    /**
     * @param first
     * @param n
     * @return
     * @throws IOException
     * @throws SocketException
     * @throws InterruptedException
     */
    private SmbNegotiation negotiate2(final Smb2NegotiateResponse first) throws IOException, SocketException {
        final int size = 0;

        final int securityMode = getRequestSecurityMode(first);

        // further negotiation needed
        final Smb2NegotiateRequest smb2neg = new Smb2NegotiateRequest(getContext().getConfig(), securityMode);
        Smb2NegotiateResponse r = null;
        byte[] negoReqBuffer = null;
        byte[] negoRespBuffer = null;
        try {
            smb2neg.setRequestCredits(Math.max(1, this.desiredCredits - this.credits.availablePermits()));

            final int reqLen = negotiateWrite(smb2neg, first != null);
            final boolean doPreauth = getContext().getConfig().getMaximumVersion().atLeast(DialectVersion.SMB311);
            if (doPreauth) {
                negoReqBuffer = new byte[reqLen];
                System.arraycopy(this.sbuf, 4, negoReqBuffer, 0, reqLen);
            }

            negotiatePeek();

            r = smb2neg.initResponse(getContext());
            final int respLen = r.decode(this.sbuf, 4);
            r.received();

            if (doPreauth) {
                negoRespBuffer = new byte[respLen];
                System.arraycopy(this.sbuf, 4, negoRespBuffer, 0, respLen);
            } else {
                negoReqBuffer = null;
            }

            if (log.isTraceEnabled()) {
                log.trace(r.toString());
                log.trace(Hexdump.toHexString(this.sbuf, 4, size));
            }
            return new SmbNegotiation(smb2neg, r, negoReqBuffer, negoRespBuffer);
        } finally {
            int grantedCredits = r != null ? r.getGrantedCredits() : 0;
            if (grantedCredits == 0) {
                grantedCredits = 1;
            }
            this.credits.release(grantedCredits);
            Arrays.fill(this.sbuf, (byte) 0);
        }
    }

    /**
     * Connect the transport
     *
     * @throws SmbException
     */
    @Override
    public boolean ensureConnected() throws SmbException {
        try {
            return super.connect(this.transportContext.getConfig().getResponseTimeout());
        } catch (final TransportException te) {
            throw new SmbException("Failed to connect: " + this.address, te);
        }

    }

    @Override
    protected void doConnect() throws IOException {
        /*
         * Negotiate Protocol Request / Response
         */
        if (log.isDebugEnabled()) {
            log.debug("Connecting in state " + this.state + " addr " + this.address.getHostAddress());
        }

        SmbNegotiation resp;
        try {
            resp = negotiate(this.port);
        } catch (final IOException ce) {
            if (!getContext().getConfig().isPort139FailoverEnabled()) {
                throw ce;
            }
            this.port = this.port == 0 || this.port == DEFAULT_PORT ? 139 : DEFAULT_PORT;
            this.smb2 = false;
            this.mid.set(0);
            resp = negotiate(this.port);
        }

        if (resp == null || resp.getResponse() == null) {
            throw new SmbException("Failed to connect.");
        }

        if (log.isDebugEnabled()) {
            log.debug("Negotiation response on " + this.name + " :" + resp);
        }

        if (!resp.getResponse().isValid(getContext(), resp.getRequest())) {
            throw new SmbException("This client is not compatible with the server.");
        }

        final boolean serverRequireSig = resp.getResponse().isSigningRequired();
        final boolean serverEnableSig = resp.getResponse().isSigningEnabled();
        if (log.isDebugEnabled()) {
            log.debug("Signature negotiation enforced " + this.signingEnforced + " (server " + serverRequireSig + ") enabled "
                    + this.getContext().getConfig().isSigningEnabled() + " (server " + serverEnableSig + ")");
        }

        /* Adjust negotiated values */
        this.tconHostName = this.address.getHostName();
        this.negotiated = resp.getResponse();
        if (resp.getResponse().getSelectedDialect().atLeast(DialectVersion.SMB311)) {
            updatePreauthHash(resp.getRequestRaw());
            updatePreauthHash(resp.getResponseRaw());
            if (log.isDebugEnabled()) {
                log.debug("Preauth hash after negotiate " + Hexdump.toHexString(this.preauthIntegrityHash));
            }
        }
    }

    protected synchronized void doDisconnect(final boolean hard) throws IOException {
        doDisconnect(hard, false);
    }

    @Override
    protected synchronized boolean doDisconnect(final boolean hard, final boolean inUse) throws IOException {
        final ListIterator<SmbSessionImpl> iter = this.sessions.listIterator();
        boolean wasInUse = false;
        final long l = getUsageCount();
        if ((inUse ? l != 1 : l > 0)) {
            log.warn("Disconnecting transport while still in use " + this + ": " + this.sessions);
            wasInUse = true;
        }

        if (log.isDebugEnabled()) {
            log.debug("Disconnecting transport " + this);
        }

        try {
            if (log.isTraceEnabled()) {
                log.trace("Currently " + this.sessions.size() + " session(s) active for " + this);
            }
            while (iter.hasNext()) {
                @SuppressWarnings("resource")
                final SmbSessionImpl ssn = iter.next();
                try {
                    wasInUse |= ssn.logoff(hard, false);
                } catch (final Exception e) {
                    log.debug("Failed to close session", e);
                } finally {
                    iter.remove();
                }
            }

            if (this.socket != null) {
                this.socket.shutdownOutput();
                this.out.close();
                this.in.close();
                this.socket.close();
                log.trace("Socket closed");
            } else {
                log.trace("Not yet initialized");
            }
        } catch (final Exception e) {
            log.debug("Exception in disconnect", e);
        } finally {
            this.socket = null;
            this.digest = null;
            this.tconHostName = null;
            this.transportContext.getTransportPool().removeTransport(this);
        }
        return wasInUse;
    }

    @Override
    protected long makeKey(final Request request) throws IOException {
        long m = this.mid.incrementAndGet() - 1;
        if (!this.smb2) {
            m = m % 32000;
        }
        ((CommonServerMessageBlock) request).setMid(m);
        return m;
    }

    @Override
    protected Long peekKey() throws IOException {
        do {
            if (readn(this.in, this.sbuf, 0, 4) < 4) {
                return null;
            }
        } while (this.sbuf[0] == (byte) 0x85); /* Dodge NetBIOS keep-alive */
        /* read smb header */
        if (readn(this.in, this.sbuf, 4, SmbConstants.SMB1_HEADER_LENGTH) < SmbConstants.SMB1_HEADER_LENGTH) {
            return null;
        }

        if (log.isTraceEnabled()) {
            log.trace("New data read: " + this);
            log.trace(Hexdump.toHexString(this.sbuf, 4, 32));
        }

        for (;;) {
            /*
             * 01234567
             * 00SSFSMB
             * 0 - 0's
             * S - size of payload
             * FSMB - 0xFF SMB magic #
             */

            if (this.sbuf[0] == (byte) 0x00 && this.sbuf[4] == (byte) 0xFE && this.sbuf[5] == (byte) 'S' && this.sbuf[6] == (byte) 'M'
                    && this.sbuf[7] == (byte) 'B') {
                this.smb2 = true;
                // also read the rest of the header
                final int lenDiff = Smb2Constants.SMB2_HEADER_LENGTH - SmbConstants.SMB1_HEADER_LENGTH;
                if (readn(this.in, this.sbuf, 4 + SmbConstants.SMB1_HEADER_LENGTH, lenDiff) < lenDiff) {
                    return null;
                }
                return (long) Encdec.dec_uint64le(this.sbuf, 28);
            }

            if (this.sbuf[0] == (byte) 0x00 && this.sbuf[1] == (byte) 0x00 && this.sbuf[4] == (byte) 0xFF && this.sbuf[5] == (byte) 'S'
                    && this.sbuf[6] == (byte) 'M' && this.sbuf[7] == (byte) 'B') {
                break; /* all good (SMB) */
            }

            /* out of phase maybe? */
            /* inch forward 1 byte and try again */
            for (int i = 0; i < 35; i++) {
                log.warn("Possibly out of phase, trying to resync " + Hexdump.toHexString(this.sbuf, 0, 16));
                this.sbuf[i] = this.sbuf[i + 1];
            }
            int b = this.in.read();
            if (b == -1) {
                return null;
            }
            this.sbuf[35] = (byte) b;
        }

        /*
         * Unless key returned is null or invalid Transport.loop() always
         * calls doRecv() after and no one else but the transport thread
         * should call doRecv(). Therefore it is ok to expect that the data
         * in sbuf will be preserved for copying into BUF in doRecv().
         */

        return (long) Encdec.dec_uint16le(this.sbuf, 34) & 0xFFFF;
    }

    @Override
    protected void doSend(final Request request) throws IOException {

        CommonServerMessageBlock smb = (CommonServerMessageBlock) request;
        final byte[] buffer = this.getContext().getBufferCache().getBuffer();
        try {
            // synchronize around encode and write so that the ordering for SMB1 signing can be maintained
            synchronized (this.outLock) {
                final int n = smb.encode(buffer, 4);
                Encdec.enc_uint32be(n & 0xFFFF, buffer, 0); /* 4 byte session message header */
                if (log.isTraceEnabled()) {
                    do {
                        log.trace(smb.toString());
                    } while (smb instanceof AndXServerMessageBlock && (smb = ((AndXServerMessageBlock) smb).getAndx()) != null);
                    log.trace(Hexdump.toHexString(buffer, 4, n));

                }
                /*
                 * For some reason this can sometimes get broken up into another
                 * "NBSS Continuation Message" frame according to WireShark
                 */

                this.out.write(buffer, 0, 4 + n);
                this.out.flush();
            }
        } finally {
            this.getContext().getBufferCache().releaseBuffer(buffer);
        }
    }

    @SuppressWarnings("unchecked")
    public <T extends CommonServerMessageBlockResponse> T sendrecv(final CommonServerMessageBlockRequest request, T response,
            final Set<RequestParam> params) throws IOException {
        response = setupResponses(request, response);

        CommonServerMessageBlockRequest curHead = request;

        final int maxSize = getContext().getConfig().getMaximumBufferSize();

        while (curHead != null) {
            CommonServerMessageBlockRequest nextHead = null;
            int totalSize = 0;
            int n = 0;
            CommonServerMessageBlockRequest last = null;
            CommonServerMessageBlockRequest chain = curHead;
            while (chain != null) {
                n++;
                final int size = chain.size();
                final int cost = chain.getCreditCost();
                final CommonServerMessageBlockRequest next = chain.getNext();
                if (log.isTraceEnabled()) {
                    log.trace(String.format("%s costs %d avail %d (%s)", chain.getClass().getName(), cost, this.credits.availablePermits(),
                            this.name));
                }
                if ((next == null || chain.allowChain(next)) && totalSize + size < maxSize && this.credits.tryAcquire(cost)) {
                    totalSize += size;
                    last = chain;
                    chain = next;
                } else if (last == null && totalSize + size > maxSize) {
                    throw new SmbException(String.format("Request size %d exceeds allowable size %d: %s", size, maxSize, chain));
                } else if (last == null) {
                    // don't have enough credits/space for the first request, block until available
                    // for space there is nothing we can do, callers need to make sure that a single message fits

                    try {
                        final long timeout = getResponseTimeout(chain);
                        if (params.contains(RequestParam.NO_TIMEOUT)) {
                            this.credits.acquire(cost);
                        } else if (!this.credits.tryAcquire(cost, timeout, TimeUnit.MILLISECONDS)) {
                            throw new SmbException("Failed to acquire credits in time");
                        }
                        totalSize += size;
                        // split off first request

                        synchronized (chain) {
                            final CommonServerMessageBlockRequest snext = chain.split();
                            nextHead = snext;
                            if (log.isDebugEnabled() && snext != null) {
                                log.debug("Insufficient credits, send only first " + chain + " next is " + snext);
                            }
                        }
                        break;
                    } catch (final InterruptedException e) {
                        final InterruptedIOException ie = new InterruptedIOException("Interrupted while acquiring credits");
                        ie.initCause(e);
                        throw ie;
                    }
                } else {
                    // not enough credits available or too big, split
                    if (log.isDebugEnabled()) {
                        log.debug("Not enough credits, split at " + last);
                    }
                    synchronized (last) {
                        nextHead = last.split();
                    }
                    break;
                }
            }

            final int reqCredits = Math.max(1, this.desiredCredits - this.credits.availablePermits() - n + 1);
            if (log.isTraceEnabled()) {
                log.trace("Request credits " + reqCredits);
            }
            request.setRequestCredits(reqCredits);

            final CommonServerMessageBlockRequest thisReq = curHead;
            try {
                CommonServerMessageBlockResponse resp = thisReq.getResponse();
                if (log.isTraceEnabled()) {
                    log.trace("Sending " + thisReq);
                }
                resp = super.sendrecv(curHead, resp, params);

                if (!checkStatus(curHead, resp)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Breaking on error " + resp);
                    }
                    break;
                }

                if (nextHead != null) {
                    // prepare remaining
                    // (e.g. set session/tree/fileid returned by the previous requests)
                    resp.prepare(nextHead);
                }
                curHead = nextHead;
            } finally {
                CommonServerMessageBlockRequest curReq = thisReq;
                int grantedCredits = 0;
                // if
                while (curReq != null) {
                    if (curReq.isResponseAsync()) {
                        log.trace("Async");
                        break;
                    }

                    final CommonServerMessageBlockResponse resp = curReq.getResponse();

                    if (resp == null) {
                        log.warn("Response not properly set up for" + curReq);
                    } else if (resp.isReceived()) {
                        grantedCredits += resp.getGrantedCredits();
                    }
                    final CommonServerMessageBlockRequest next = curReq.getNext();
                    if (next == null) {
                        break;
                    }
                    curReq = next;
                }
                if (!isDisconnected() && !curReq.isResponseAsync() && !curReq.getResponse().isAsync() && !curReq.getResponse().isError()
                        && grantedCredits == 0) {
                    if (this.credits.availablePermits() > 0 || n > 0) {
                        log.debug("Server " + this + " returned zero credits for " + curReq);
                    } else {
                        log.warn("Server " + this + " took away all our credits");
                    }
                } else if (!curReq.isResponseAsync()) {
                    if (log.isTraceEnabled()) {
                        log.trace("Adding credits " + grantedCredits);
                    }
                    this.credits.release(grantedCredits);
                }
            }
        }

        if (!response.isReceived()) {
            throw new IOException("No response", response.getException());
        }
        return response;

    }

    private <T extends CommonServerMessageBlockResponse> T setupResponses(final CommonServerMessageBlockRequest request, T response)
            throws IOException {
        if (request instanceof org.codelibs.jcifs.smb.internal.Request) {
            if (response == null) {
                response = (T) ((org.codelibs.jcifs.smb.internal.Request<?>) request).initResponse(getContext());
            } else if (isSMB2()) {
                throw new IOException("Should not provide response argument for SMB2");
            }
        } else if (request instanceof AndXServerMessageBlock curReq && response instanceof AndXServerMessageBlock curResp) {
            do {
                curReq.setResponse(curResp);

                final ServerMessageBlock nextReq = curReq.getAndx();
                if (nextReq == null) {
                    break;
                }
                final ServerMessageBlock nextResp = curResp.getAndx();
                nextReq.setResponse(nextReq);

                if (!(nextReq instanceof AndXServerMessageBlock) || !(nextResp instanceof AndXServerMessageBlock)) {
                    break;
                }
                curReq = (AndXServerMessageBlock) nextReq;
                curResp = (AndXServerMessageBlock) nextResp;

            } while (true);
        } else {
            request.setResponse(response);
        }
        if (response == null) {
            throw new IOException("Invalid response");
        }
        return response;
    }

    @Override
    protected <T extends Response> boolean handleIntermediate(final Request request, final T response) {
        if (!this.smb2) {
            return false;
        }
        final ServerMessageBlock2Request<?> req = (ServerMessageBlock2Request<?>) request;
        final ServerMessageBlock2Response resp = (ServerMessageBlock2Response) response;
        synchronized (resp) {
            if (resp.isAsync() && !resp.isAsyncHandled() && resp.getStatus() == NtStatus.NT_STATUS_PENDING && resp.getAsyncId() != 0) {
                resp.setAsyncHandled(true);
                final boolean first = !req.isAsync();
                req.setAsyncId(resp.getAsyncId());
                final Long exp = resp.getExpiration();
                if (exp != null) {
                    resp.setExpiration(System.currentTimeMillis() + getResponseTimeout(request));
                }
                if (log.isDebugEnabled()) {
                    log.debug("Have intermediate reply " + response);
                }

                if (first) {
                    final int credit = resp.getCredit();
                    if (log.isDebugEnabled()) {
                        log.debug("Credit from intermediate " + credit);
                    }
                    this.credits.release(credit);
                }
                return true;
            }
        }
        return false;
    }

    protected void doSend0(final Request request) throws IOException {
        try {
            doSend(request);
        } catch (final IOException ioe) {
            log.warn("send failed", ioe);
            try {
                disconnect(true);
            } catch (final IOException ioe2) {
                ioe.addSuppressed(ioe2);
                log.error("disconnect failed", ioe2);
            }
            throw ioe;
        }
    }

    // must be synchronized with peekKey
    @Override
    protected void doRecv(final Response response) throws IOException {
        final CommonServerMessageBlock resp = (CommonServerMessageBlock) response;
        this.negotiated.setupResponse(response);
        try {
            if (this.smb2) {
                doRecvSMB2(resp);
            } else {
                doRecvSMB1(resp);
            }
        } catch (final Exception e) {
            log.warn("Failure decoding message, disconnecting transport", e);
            response.exception(e);
            synchronized (response) {
                response.notifyAll();
            }
            throw e;
        }

    }

    /**
     * @param response
     * @throws IOException
     * @throws SMBProtocolDecodingException
     */
    private void doRecvSMB2(final CommonServerMessageBlock response) throws IOException, SMBProtocolDecodingException {
        int size = Encdec.dec_uint16be(this.sbuf, 2) & 0xFFFF | (this.sbuf[1] & 0xFF) << 16;
        if (size < Smb2Constants.SMB2_HEADER_LENGTH + 1) {
            throw new IOException("Invalid payload size: " + size);
        }

        if (this.sbuf[0] != (byte) 0x00 || this.sbuf[4] != (byte) 0xFE || this.sbuf[5] != (byte) 'S' || this.sbuf[6] != (byte) 'M'
                || this.sbuf[7] != (byte) 'B') {
            throw new IOException("Houston we have a synchronization problem");
        }

        int nextCommand = Encdec.dec_uint32le(this.sbuf, 4 + 20);
        final int maximumBufferSize = getContext().getConfig().getMaximumBufferSize();
        final int msgSize = nextCommand != 0 ? nextCommand : size;
        if (msgSize > maximumBufferSize) {
            throw new IOException(String.format("Message size %d exceeds maxiumum buffer size %d", msgSize, maximumBufferSize));
        }

        ServerMessageBlock2Response cur = (ServerMessageBlock2Response) response;
        final byte[] buffer = getContext().getBufferCache().getBuffer();
        try {
            int rl = nextCommand != 0 ? nextCommand : size;

            // read and decode first
            System.arraycopy(this.sbuf, 4, buffer, 0, Smb2Constants.SMB2_HEADER_LENGTH);
            readn(this.in, buffer, Smb2Constants.SMB2_HEADER_LENGTH, rl - Smb2Constants.SMB2_HEADER_LENGTH);

            cur.setReadSize(rl);
            int len = cur.decode(buffer, 0);

            if (len > rl) {
                throw new IOException(String.format("WHAT? ( read %d decoded %d ): %s", rl, len, cur));
            }
            if (nextCommand != 0 && len > nextCommand) {
                throw new IOException("Overlapping commands");
            }
            size -= rl;

            while (size > 0 && nextCommand != 0) {
                cur = (ServerMessageBlock2Response) cur.getNextResponse();
                if (cur == null) {
                    log.warn("Response not properly set up");
                    this.in.skip(size);
                    break;
                }

                // read next header
                readn(this.in, buffer, 0, Smb2Constants.SMB2_HEADER_LENGTH);
                nextCommand = Encdec.dec_uint32le(buffer, 20);

                if ((nextCommand != 0 ? nextCommand > maximumBufferSize : size > maximumBufferSize)) {
                    throw new IOException(String.format("Message size %d exceeds maxiumum buffer size %d",
                            nextCommand != 0 ? nextCommand : size, maximumBufferSize));
                }

                rl = nextCommand != 0 ? nextCommand : size;

                if (log.isDebugEnabled()) {
                    log.debug(String.format("Compound next command %d read size %d remain %d", nextCommand, rl, size));
                }

                cur.setReadSize(rl);
                readn(this.in, buffer, Smb2Constants.SMB2_HEADER_LENGTH, rl - Smb2Constants.SMB2_HEADER_LENGTH);

                len = cur.decode(buffer, 0, true);
                if (len > rl) {
                    throw new IOException(String.format("WHAT? ( read %d decoded %d ): %s", rl, len, cur));
                }
                if (nextCommand != 0 && len > nextCommand) {
                    throw new IOException("Overlapping commands");
                }
                size -= rl;
            }
        } finally {
            getContext().getBufferCache().releaseBuffer(buffer);
        }
    }

    /**
     * @param resp
     * @throws IOException
     * @throws SMBProtocolDecodingException
     */
    private void doRecvSMB1(final CommonServerMessageBlock resp) throws IOException, SMBProtocolDecodingException {
        final byte[] buffer = getContext().getBufferCache().getBuffer();
        try {
            System.arraycopy(this.sbuf, 0, buffer, 0, 4 + SMB1_HEADER_LENGTH);
            final int size = Encdec.dec_uint16be(buffer, 2) & 0xFFFF;
            if (size < SMB1_HEADER_LENGTH + 1 || 4 + size > Math.min(0xFFFF, getContext().getConfig().getMaximumBufferSize())) {
                throw new IOException("Invalid payload size: " + size);
            }
            final int errorCode = Encdec.dec_uint32le(buffer, 9) & 0xFFFFFFFF;
            if (resp.getCommand() == ServerMessageBlock.SMB_COM_READ_ANDX
                    && (errorCode == 0 || errorCode == NtStatus.NT_STATUS_BUFFER_OVERFLOW)) {
                // overflow indicator normal for pipe
                final SmbComReadAndXResponse r = (SmbComReadAndXResponse) resp;
                int off = SMB1_HEADER_LENGTH;
                /* WordCount thru dataOffset always 27 */
                readn(this.in, buffer, 4 + off, 27);
                off += 27;
                resp.decode(buffer, 4);
                /* EMC can send pad w/o data */
                final int pad = r.getDataOffset() - off;
                if (r.getByteCount() > 0 && pad > 0 && pad < 4) {
                    readn(this.in, buffer, 4 + off, pad);
                }

                if (r.getDataLength() > 0) {
                    readn(this.in, r.getData(), r.getOffset(), r.getDataLength()); /* read direct */
                }
            } else {
                readn(this.in, buffer, 4 + SMB1_HEADER_LENGTH, size - SMB1_HEADER_LENGTH);
                resp.decode(buffer, 4);
            }
        } finally {
            getContext().getBufferCache().releaseBuffer(buffer);
        }
    }

    @Override
    protected void doSkip(final Long key) throws IOException {
        synchronized (this.inLock) {
            final int size = Encdec.dec_uint16be(this.sbuf, 2) & 0xFFFF;
            if (size < 33 || 4 + size > this.getContext().getConfig().getReceiveBufferSize()) {
                /* log message? */
                log.warn("Flusing stream input");
                this.in.skip(this.in.available());
            } else {
                final Response notification = createNotification(key);
                if (notification != null) {
                    log.debug("Parsing notification");
                    doRecv(notification);
                    handleNotification(notification);
                    return;
                }
                log.warn("Skipping message " + key);
                if (this.isSMB2()) {
                    this.in.skip(size - Smb2Constants.SMB2_HEADER_LENGTH);
                } else {
                    this.in.skip(size - SmbConstants.SMB1_HEADER_LENGTH);
                }
            }
        }
    }

    /**
     * @param notification
     */
    protected void handleNotification(final Response notification) {
        log.info("Received notification " + notification);
    }

    /**
     * @param key
     * @return
     * @throws SmbException
     */
    protected Response createNotification(final Long key) throws SmbException {
        if (key == null) {
            // no valid header
            return null;
        }
        if (this.smb2) {
            if (key != -1) {
                return null;
            }
            final int cmd = Encdec.dec_uint16le(this.sbuf, 4 + 12) & 0xFFFF;
            if (cmd == 0x12) {
                return new Smb2OplockBreakNotification(getContext().getConfig());
            }
        } else {
            if (key != 0xFFFF) {
                return null;
            }
            final int cmd = this.sbuf[4 + 4];
            if (cmd == 0x24) {
                return new SmbComLockingAndX(getContext().getConfig());
            }
        }
        return null;
    }

    boolean checkStatus(final ServerMessageBlock req, final ServerMessageBlock resp) throws SmbException {
        boolean cont = false;
        if (resp.getErrorCode() == 0x30002) {
            // if using DOS error codes this indicates a DFS referral
            resp.setErrorCode(NtStatus.NT_STATUS_PATH_NOT_COVERED);
        } else {
            resp.setErrorCode(SmbException.getStatusByCode(resp.getErrorCode()));
        }
        switch (resp.getErrorCode()) {
        case NtStatus.NT_STATUS_SUCCESS:
            cont = true;
            break;
        case NtStatus.NT_STATUS_ACCESS_DENIED:
        case NtStatus.NT_STATUS_WRONG_PASSWORD:
        case NtStatus.NT_STATUS_LOGON_FAILURE:
        case NtStatus.NT_STATUS_ACCOUNT_RESTRICTION:
        case NtStatus.NT_STATUS_INVALID_LOGON_HOURS:
        case NtStatus.NT_STATUS_INVALID_WORKSTATION:
        case NtStatus.NT_STATUS_PASSWORD_EXPIRED:
        case NtStatus.NT_STATUS_ACCOUNT_DISABLED:
        case NtStatus.NT_STATUS_ACCOUNT_LOCKED_OUT:
        case NtStatus.NT_STATUS_TRUSTED_DOMAIN_FAILURE:
            throw new SmbAuthException(resp.getErrorCode());
        case 0xC00000BB: // NT_STATUS_NOT_SUPPORTED
            throw new SmbUnsupportedOperationException();
        case NtStatus.NT_STATUS_PATH_NOT_COVERED:
            // samba fails to report the proper status for some operations
        case 0xC00000A2: // NT_STATUS_MEDIA_WRITE_PROTECTED
            checkReferral(resp, req.getPath(), req);
        case NtStatus.NT_STATUS_BUFFER_OVERFLOW:
            break; /* normal for DCERPC named pipes */
        case NtStatus.NT_STATUS_MORE_PROCESSING_REQUIRED:
            break; /* normal for NTLMSSP */
        default:
            if (log.isDebugEnabled()) {
                log.debug("Error code: 0x" + Hexdump.toHexString(resp.getErrorCode(), 8) + " for " + req.getClass().getSimpleName());
            }
            throw new SmbException(resp.getErrorCode(), null);
        }
        if (resp.isVerifyFailed()) {
            throw new SmbException("Signature verification failed.");
        }
        return cont;
    }

    /**
     * @param request
     * @param response
     * @throws SmbException
     */
    boolean checkStatus2(final ServerMessageBlock2 req, final Response resp) throws SmbException {
        boolean cont = false;
        switch (resp.getErrorCode()) {
        case NtStatus.NT_STATUS_SUCCESS:
        case NtStatus.NT_STATUS_NO_MORE_FILES:
            cont = true;
            break;
        case NtStatus.NT_STATUS_PENDING:
            // must be the last
            cont = false;
            break;
        case NtStatus.NT_STATUS_ACCESS_DENIED:
        case NtStatus.NT_STATUS_WRONG_PASSWORD:
        case NtStatus.NT_STATUS_LOGON_FAILURE:
        case NtStatus.NT_STATUS_ACCOUNT_RESTRICTION:
        case NtStatus.NT_STATUS_INVALID_LOGON_HOURS:
        case NtStatus.NT_STATUS_INVALID_WORKSTATION:
        case NtStatus.NT_STATUS_PASSWORD_EXPIRED:
        case NtStatus.NT_STATUS_ACCOUNT_DISABLED:
        case NtStatus.NT_STATUS_ACCOUNT_LOCKED_OUT:
        case NtStatus.NT_STATUS_TRUSTED_DOMAIN_FAILURE:
            throw new SmbAuthException(resp.getErrorCode());
        case NtStatus.NT_STATUS_MORE_PROCESSING_REQUIRED:
            break; /* normal for SPNEGO */
        case 0x10B: // NT_STATUS_NOTIFY_CLEANUP:
        case NtStatus.NT_STATUS_NOTIFY_ENUM_DIR:
            break;
        case 0xC00000BB: // NT_STATUS_NOT_SUPPORTED
        case 0xC0000010: // NT_STATUS_INVALID_DEVICE_REQUEST
            throw new SmbUnsupportedOperationException();
        case NtStatus.NT_STATUS_PATH_NOT_COVERED:
            if (!(req instanceof RequestWithPath)) {
                throw new SmbException("Invalid request for a DFS NT_STATUS_PATH_NOT_COVERED response " + req.getClass().getName());
            }
            final String path = ((RequestWithPath) req).getFullUNCPath();
            checkReferral(resp, path, (RequestWithPath) req);
            // checkReferral always throws and exception but put break here for clarity
            break;
        case NtStatus.NT_STATUS_BUFFER_OVERFLOW:
            if (resp instanceof Smb2ReadResponse) {
                break;
            }
            if (resp instanceof Smb2IoctlResponse) {
                final int ctlCode = ((Smb2IoctlResponse) resp).getCtlCode();
                if (ctlCode == Smb2IoctlRequest.FSCTL_PIPE_TRANSCEIVE || ctlCode == Smb2IoctlRequest.FSCTL_PIPE_PEEK) {
                    break;
                }
            }
            // fall through
        default:
            if (log.isDebugEnabled()) {
                log.debug("Error code: 0x" + Hexdump.toHexString(resp.getErrorCode(), 8) + " for " + req.getClass().getSimpleName());
            }
            throw new SmbException(resp.getErrorCode(), null);
        }
        if (resp.isVerifyFailed()) {
            throw new SMBSignatureValidationException("Signature verification failed.");
        }
        return cont;
    }

    /**
     * @param resp
     * @param path
     * @param req
     * @throws SmbException
     * @throws DfsReferral
     */
    private void checkReferral(final Response resp, final String path, final RequestWithPath req) throws SmbException, DfsReferral {
        DfsReferralData dr = null;
        if (!getContext().getConfig().isDfsDisabled()) {
            try {
                dr = getDfsReferrals(getContext(), path, req.getServer(), req.getDomain(), 0);
            } catch (final CIFSException e) {
                throw new SmbException("Failed to get DFS referral", e);
            }
        }
        if (dr == null) {
            if (log.isDebugEnabled()) {
                log.debug("Error code: 0x" + Hexdump.toHexString(resp.getErrorCode(), 8));
            }
            throw new SmbException(resp.getErrorCode(), null);
        }

        if (req.getDomain() != null && getContext().getConfig().isDfsConvertToFQDN() && dr instanceof DfsReferralDataImpl) {
            ((DfsReferralDataImpl) dr).fixupDomain(req.getDomain());
        }
        if (log.isDebugEnabled()) {
            log.debug("Got referral " + dr);
        }

        getContext().getDfs().cache(getContext(), path, dr);
        throw new DfsReferral(dr);
    }

    <T extends CommonServerMessageBlockResponse> T send(final CommonServerMessageBlockRequest request, final T response)
            throws SmbException {
        return send(request, response, Collections.<RequestParam> emptySet());
    }

    <T extends CommonServerMessageBlockResponse> T send(final CommonServerMessageBlockRequest request, T response,
            final Set<RequestParam> params) throws SmbException {
        ensureConnected(); /* must negotiate before we can test flags2, useUnicode, etc */
        if (this.smb2 && !(request instanceof ServerMessageBlock2)) {
            throw new SmbException("Not an SMB2 request " + request.getClass().getName());
        }
        if (!this.smb2 && !(request instanceof ServerMessageBlock)) {
            throw new SmbException("Not an SMB1 request");
        }

        this.negotiated.setupRequest(request);

        if (response != null) {
            request.setResponse(response); /* needed by sign */
            response.setDigest(request.getDigest());
        }

        try {
            if (log.isTraceEnabled()) {
                log.trace("Sending " + request);
            }
            if (request.isCancel()) {
                doSend0(request);
                return null;
            }
            if (request instanceof SmbComTransaction) {
                response = sendComTransaction(request, response, params);
            } else {
                if (response != null) {
                    response.setCommand(request.getCommand());
                }
                response = sendrecv(request, response, params);
            }
        } catch (final SmbException se) {
            throw se;
        } catch (final IOException ioe) {
            throw new SmbException(ioe.getMessage(), ioe);
        }

        if (log.isTraceEnabled()) {
            log.trace("Response is " + response);
        }

        checkStatus(request, response);
        return response;
    }

    /**
     * @param request
     * @param response
     * @throws SmbException
     */
    private <T extends CommonServerMessageBlockResponse> boolean checkStatus(final CommonServerMessageBlockRequest request,
            final T response) throws SmbException {
        CommonServerMessageBlockRequest cur = request;
        while (cur != null) {
            if (this.smb2) {
                if (!checkStatus2((ServerMessageBlock2) cur, cur.getResponse())) {
                    return false;
                }
            } else if (!checkStatus((ServerMessageBlock) cur, (ServerMessageBlock) cur.getResponse())) {
                return false;
            }
            cur = cur.getNext();
        }
        return true;
    }

    /**
     * @param request
     * @param response
     * @param params
     * @throws IOException
     * @throws SmbException
     * @throws TransportException
     * @throws EOFException
     */
    private <T extends CommonServerMessageBlock & Response> T sendComTransaction(final CommonServerMessageBlockRequest request,
            final T response, final Set<RequestParam> params) throws IOException, SmbException, TransportException, EOFException {
        response.setCommand(request.getCommand());
        final SmbComTransaction req = (SmbComTransaction) request;
        final SmbComTransactionResponse resp = (SmbComTransactionResponse) response;
        resp.reset();

        long k;

        /*
         * First request w/ interim response
         */
        try {
            req.setBuffer(getContext().getBufferCache().getBuffer());
            req.nextElement();
            if (req.hasMoreElements()) {
                final SmbComBlankResponse interim = new SmbComBlankResponse(getContext().getConfig());
                super.sendrecv(req, interim, params);
                if (interim.getErrorCode() != 0) {
                    checkStatus(req, interim);
                }
                k = req.nextElement().getMid();
            } else {
                k = makeKey(req);
            }

            try {
                resp.clearReceived();
                long timeout = getResponseTimeout(req);
                if (!params.contains(RequestParam.NO_TIMEOUT)) {
                    resp.setExpiration(System.currentTimeMillis() + timeout);
                } else {
                    resp.setExpiration(null);
                }

                final byte[] txbuf = getContext().getBufferCache().getBuffer();
                resp.setBuffer(txbuf);

                this.response_map.put(k, resp);

                /*
                 * Send multiple fragments
                 */

                do {
                    doSend0(req);
                } while (req.hasMoreElements() && req.nextElement() != null);

                /*
                 * Receive multiple fragments
                 */
                synchronized (resp) {
                    while (!resp.isReceived() || resp.hasMoreElements()) {
                        if (!params.contains(RequestParam.NO_TIMEOUT)) {
                            resp.wait(timeout);
                            timeout = resp.getExpiration() - System.currentTimeMillis();
                            if (timeout <= 0) {
                                throw new TransportException(this + " timedout waiting for response to " + req);
                            }
                        } else {
                            resp.wait();
                            if (log.isTraceEnabled()) {
                                log.trace("Wait returned " + isDisconnected());
                            }
                            if (isDisconnected()) {
                                throw new EOFException("Transport closed while waiting for result");
                            }
                        }
                    }
                }

                if (!resp.isReceived()) {
                    throw new TransportException("Failed to read response");
                }

                if (resp.getErrorCode() != 0) {
                    checkStatus(req, resp);
                }
                return response;
            } finally {
                this.response_map.remove(k);
                getContext().getBufferCache().releaseBuffer(resp.releaseBuffer());
            }
        } catch (final InterruptedException ie) {
            throw new TransportException(ie);
        } finally {
            getContext().getBufferCache().releaseBuffer(req.releaseBuffer());
        }

    }

    @Override
    public String toString() {
        return super.toString() + "[" + this.address + ":" + this.port + ",state=" + this.state + ",signingEnforced=" + this.signingEnforced
                + ",usage=" + this.getUsageCount() + "]";
    }

    /* DFS */
    @Override
    public DfsReferralData getDfsReferrals(final CIFSContext ctx, final String path, final String targetHost, final String targetDomain,
            int rn) throws CIFSException {
        if (log.isDebugEnabled()) {
            log.debug("Resolving DFS path " + path);
        }

        if (path.length() >= 2 && path.charAt(0) == '\\' && path.charAt(1) == '\\') {
            throw new SmbException("Path must not start with double slash: " + path);
        }

        try (SmbSessionImpl sess = getSmbSession(ctx, targetHost, targetDomain);
                SmbTransportImpl transport = sess.getTransport();
                SmbTreeImpl ipc = sess.getSmbTree("IPC$", null)) {

            final DfsReferralRequestBuffer dfsReq = new DfsReferralRequestBuffer(path, 3);
            DfsReferralResponseBuffer dfsResp;
            if (isSMB2()) {
                final Smb2IoctlRequest req = new Smb2IoctlRequest(ctx.getConfig(), Smb2IoctlRequest.FSCTL_DFS_GET_REFERRALS);
                req.setFlags(Smb2IoctlRequest.SMB2_O_IOCTL_IS_FSCTL);
                req.setInputData(dfsReq);
                dfsResp = ipc.send(req).getOutputData(DfsReferralResponseBuffer.class);
            } else {
                final Trans2GetDfsReferralResponse resp = new Trans2GetDfsReferralResponse(ctx.getConfig());
                ipc.send(new Trans2GetDfsReferral(ctx.getConfig(), path), resp);
                dfsResp = resp.getDfsResponse();
            }

            if (dfsResp.getNumReferrals() == 0) {
                return null;
            }
            if (rn == 0 || dfsResp.getNumReferrals() < rn) {
                rn = dfsResp.getNumReferrals();
            }

            DfsReferralDataImpl cur = null;
            final long expiration = System.currentTimeMillis() + ctx.getConfig().getDfsTtl() * 1000;
            final Referral[] refs = dfsResp.getReferrals();
            for (int di = 0; di < rn; di++) {
                final DfsReferralDataImpl dr = DfsReferralDataImpl.fromReferral(refs[di], path, expiration, dfsResp.getPathConsumed());
                dr.setDomain(targetDomain);

                if ((dfsResp.getTflags() & 0x2) == 0 && (dr.getFlags() & 0x2) == 0) {
                    log.debug("Non-root referral is not final " + dfsResp);
                    dr.intermediate();
                }

                if ((cur != null)) {
                    cur.append(dr);
                }
                cur = dr;
            }

            if (log.isDebugEnabled()) {
                log.debug("Got referral " + cur);
            }
            return cur;
        }
    }

    byte[] getPreauthIntegrityHash() {
        return this.preauthIntegrityHash;
    }

    private void updatePreauthHash(final byte[] input) throws CIFSException {
        synchronized (this.preauthIntegrityHash) {
            this.preauthIntegrityHash = calculatePreauthHash(input, 0, input.length, this.preauthIntegrityHash);
        }
    }

    byte[] calculatePreauthHash(final byte[] input, final int off, final int len, final byte[] oldHash) throws CIFSException {
        if (!this.smb2 || this.negotiated == null) {
            throw new SmbUnsupportedOperationException();
        }

        final Smb2NegotiateResponse resp = (Smb2NegotiateResponse) this.negotiated;
        if (!resp.getSelectedDialect().atLeast(DialectVersion.SMB311)) {
            throw new SmbUnsupportedOperationException();
        }

        MessageDigest dgst = switch (resp.getSelectedPreauthHash()) {
        case 1 -> Crypto.getSHA512();
        default -> throw new SmbUnsupportedOperationException();
        };
        if (oldHash != null) {
            dgst.update(oldHash);
        }
        dgst.update(input, off, len);
        return dgst.digest();
    }

    /**
     * Create encryption context for SMB3 encrypted communication
     *
     * @param sessionKey the session key from GSS-API authentication
     * @param preauthHash the pre-authentication integrity hash (SMB 3.1.1 only)
     * @return encryption context
     * @throws CIFSException if encryption is not supported or fails
     */
    Smb2EncryptionContext createEncryptionContext(final byte[] sessionKey, final byte[] preauthHash) throws CIFSException {
        if (!this.smb2 || this.negotiated == null) {
            throw new SmbUnsupportedOperationException("SMB2/SMB3 required for encryption");
        }

        final Smb2NegotiateResponse resp = (Smb2NegotiateResponse) this.negotiated;
        final DialectVersion dialect = resp.getSelectedDialect();
        int cipherId = -1;

        if (dialect.atLeast(DialectVersion.SMB311)) {
            cipherId = resp.getSelectedCipher();
            if (cipherId == -1) {
                // Default to AES-128-GCM for SMB 3.1.1 if no cipher negotiated
                cipherId = EncryptionNegotiateContext.CIPHER_AES128_GCM;
            }
        } else if (dialect.atLeast(DialectVersion.SMB300)) {
            // SMB 3.0/3.0.2 only supports AES-128-CCM
            cipherId = EncryptionNegotiateContext.CIPHER_AES128_CCM;
        } else {
            throw new SmbUnsupportedOperationException("SMB3 required for encryption, negotiated: " + dialect);
        }

        try {
            // Derive encryption and decryption keys using SMB3 KDF
            final int dialectInt = dialect.getDialect();
            final byte[] encryptionKey = Smb3KeyDerivation.deriveEncryptionKey(dialectInt, sessionKey, preauthHash);
            final byte[] decryptionKey = Smb3KeyDerivation.deriveDecryptionKey(dialectInt, sessionKey, preauthHash);

            return new Smb2EncryptionContext(cipherId, dialect, encryptionKey, decryptionKey);
        } catch (final Exception e) {
            throw new CIFSException("Failed to create encryption context", e);
        }
    }

    public int getRequestSecurityMode(final Smb2NegotiateResponse first) {
        int securityMode = Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED;
        if (this.signingEnforced || first != null && first.isSigningRequired()) {
            securityMode = Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED | Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED;
        }

        return securityMode;
    }
}
