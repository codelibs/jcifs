/* jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
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

package jcifs.smb;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import javax.security.auth.Subject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.DialectVersion;
import jcifs.RuntimeCIFSException;
import jcifs.SmbConstants;
import jcifs.SmbSession;
import jcifs.internal.CommonServerMessageBlock;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.CommonServerMessageBlockResponse;
import jcifs.internal.RequestWithPath;
import jcifs.internal.SMBSigningDigest;
import jcifs.internal.smb1.SMB1SigningDigest;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.smb1.com.SmbComBlankResponse;
import jcifs.internal.smb1.com.SmbComLogoffAndX;
import jcifs.internal.smb1.com.SmbComNegotiateResponse;
import jcifs.internal.smb1.com.SmbComSessionSetupAndX;
import jcifs.internal.smb1.com.SmbComSessionSetupAndXResponse;
import jcifs.internal.smb1.com.SmbComTreeConnectAndX;
import jcifs.internal.smb2.ServerMessageBlock2;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.smb2.Smb2EncryptionContext;
import jcifs.internal.smb2.Smb2SigningDigest;
import jcifs.internal.smb2.lease.LeaseManager;
import jcifs.internal.smb2.multichannel.ChannelInfo;
import jcifs.internal.smb2.multichannel.ChannelManager;
import jcifs.internal.smb2.nego.Smb2NegotiateResponse;
import jcifs.internal.smb2.persistent.PersistentHandleManager;
import jcifs.internal.smb2.session.Smb2LogoffRequest;
import jcifs.internal.smb2.session.Smb2SessionSetupRequest;
import jcifs.internal.smb2.session.Smb2SessionSetupResponse;
import jcifs.internal.witness.WitnessClient;
import jcifs.internal.witness.WitnessNotification;
import jcifs.internal.witness.WitnessRegistration;
import jcifs.util.Hexdump;

/**
 *
 */
final class SmbSessionImpl implements SmbSessionInternal {

    private static final Logger log = LoggerFactory.getLogger(SmbSessionImpl.class);

    /*
     * 0 - not connected
     * 1 - connecting
     * 2 - connected
     * 3 - disconnecting
     */
    private final AtomicInteger connectionState = new AtomicInteger();
    private int uid;
    private List<SmbTreeImpl> trees;

    private final SmbTransportImpl transport;
    private long expiration;
    private String netbiosName = null;

    private CIFSContext transportContext;

    private CredentialsInternal credentials;
    private byte[] sessionKey;
    private boolean extendedSecurity;

    private final AtomicLong usageCount = new AtomicLong(1);
    private final AtomicBoolean transportAcquired = new AtomicBoolean(true);

    private long sessionId;

    private SMBSigningDigest digest;
    private Smb2EncryptionContext encryptionContext;

    private final String targetDomain;
    private final String targetHost;

    private byte[] preauthIntegrityHash;

    // Multi-channel support
    private ChannelManager channelManager;

    // Witness protocol support fields
    private WitnessClient witnessClient;
    private boolean witnessEnabled;

    // SMB3 lease support
    private LeaseManager leaseManager;

    // SMB3 persistent handle support
    private PersistentHandleManager persistentHandleManager;

    SmbSessionImpl(CIFSContext tf, String targetHost, String targetDomain, SmbTransportImpl transport) {
        this.transportContext = tf;
        this.targetDomain = targetDomain;
        this.targetHost = targetHost;
        this.transport = transport.acquire();
        this.trees = new CopyOnWriteArrayList<>();
        this.credentials = tf.getCredentials().unwrap(CredentialsInternal.class).clone();

        // Initialize multi-channel support
        this.channelManager = new ChannelManager(tf, this);

        // Initialize SMB3 feature managers
        this.leaseManager = new LeaseManager(tf);
        this.persistentHandleManager = new PersistentHandleManager(tf);
    }

    /**
     * @return the configuration used by this session
     */
    @Override
    public Configuration getConfig() {
        return this.transportContext.getConfig();
    }

    /**
     * @return the targetDomain
     */
    public String getTargetDomain() {
        return this.targetDomain;
    }

    /**
     * @return the targetHost
     */
    public String getTargetHost() {
        return this.targetHost;
    }

    /**
     * @return whether the session is in use
     */
    @Override
    public boolean isInUse() {
        return this.usageCount.get() > 0;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbSession#unwrap(java.lang.Class)
     */
    @SuppressWarnings("unchecked")
    @Override
    public <T extends SmbSession> T unwrap(Class<T> type) {
        if (type.isAssignableFrom(this.getClass())) {
            return (T) this;
        }
        throw new ClassCastException();
    }

    /**
     * @return session increased usage count
     */
    public SmbSessionImpl acquire() {
        long usage = this.usageCount.incrementAndGet();
        if (log.isTraceEnabled()) {
            log.trace("Acquire session " + usage + " " + this);
        }

        if (usage == 1) {
            synchronized (this) {
                if (this.transportAcquired.compareAndSet(false, true)) {
                    log.debug("Reacquire transport");
                    this.transport.acquire();
                }
            }
        }

        return this;
    }

    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#finalize()
     */
    @Override
    protected void finalize() throws Throwable {
        try {
            if (isConnected() && this.usageCount.get() != 0) {
                log.warn("Session was not properly released, performing emergency cleanup: " + this);
                // Perform emergency cleanup to prevent memory leaks
                emergencyCleanup();
            }
        } catch (Exception e) {
            log.error("Error during session finalization", e);
        } finally {
            super.finalize();
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see java.lang.AutoCloseable#close()
     */
    @Override
    public void close() {
        release();
    }

    /**
     *
     */
    public void release() {
        long usage = this.usageCount.decrementAndGet();
        if (log.isTraceEnabled()) {
            log.trace("Release session " + usage + " " + this);
        }

        if (usage == 0) {
            if (log.isDebugEnabled()) {
                log.debug("Usage dropped to zero, release connection " + this.transport);
            }
            // Ensure atomic cleanup of all resources
            synchronized (this) {
                // Double-check usage count within synchronized block
                if (this.usageCount.get() != 0) {
                    return; // Another thread acquired the session
                }

                if (this.transportAcquired.compareAndSet(true, false)) {
                    this.transport.release();
                }

                // Shutdown channel manager
                if (this.channelManager != null) {
                    this.channelManager.shutdown();
                    this.channelManager = null;
                }

                // Shutdown witness client
                if (this.witnessClient != null) {
                    this.witnessClient.close();
                    this.witnessClient = null;
                    this.witnessEnabled = false;
                }

                // Clear trees collection atomically
                if (this.trees != null) {
                    this.trees.clear();
                }
            }
        } else if (usage < 0) {
            throw new RuntimeCIFSException("Usage count dropped below zero");
        }
    }

    /**
     * Emergency cleanup method called during finalization to prevent memory leaks
     */
    private void emergencyCleanup() {
        try {
            // Force usage count to zero to trigger cleanup
            this.usageCount.set(0);

            synchronized (this) {
                // Emergency release of transport
                if (this.transportAcquired.compareAndSet(true, false)) {
                    try {
                        this.transport.release();
                    } catch (Exception e) {
                        log.debug("Error releasing transport during emergency cleanup", e);
                    }
                }

                // Emergency shutdown of managers
                if (this.channelManager != null) {
                    try {
                        this.channelManager.shutdown();
                        this.channelManager = null;
                    } catch (Exception e) {
                        log.debug("Error shutting down channel manager during emergency cleanup", e);
                    }
                }

                if (this.witnessClient != null) {
                    try {
                        this.witnessClient.close();
                        this.witnessClient = null;
                        this.witnessEnabled = false;
                    } catch (Exception e) {
                        log.debug("Error closing witness client during emergency cleanup", e);
                    }
                }

                if (this.leaseManager != null) {
                    try {
                        this.leaseManager.shutdown();
                        this.leaseManager = null;
                    } catch (Exception e) {
                        log.debug("Error shutting down lease manager during emergency cleanup", e);
                    }
                }

                if (this.persistentHandleManager != null) {
                    try {
                        this.persistentHandleManager.shutdown();
                        this.persistentHandleManager = null;
                    } catch (Exception e) {
                        log.debug("Error shutting down persistent handle manager during emergency cleanup", e);
                    }
                }

                // Emergency cleanup of trees
                if (this.trees != null) {
                    try {
                        // Clear all tree references
                        for (SmbTreeImpl tree : this.trees) {
                            try {
                                // Force release trees during emergency cleanup
                                tree.release();
                            } catch (Exception e) {
                                log.debug("Error during emergency tree cleanup", e);
                            }
                        }
                        this.trees.clear();
                    } catch (Exception e) {
                        log.debug("Error clearing trees during emergency cleanup", e);
                    }
                }

                // Clear sensitive data
                if (this.sessionKey != null) {
                    java.util.Arrays.fill(this.sessionKey, (byte) 0);
                    this.sessionKey = null;
                }

                if (this.preauthIntegrityHash != null) {
                    java.util.Arrays.fill(this.preauthIntegrityHash, (byte) 0);
                    this.preauthIntegrityHash = null;
                }

                // Clear encryption context
                if (this.encryptionContext != null) {
                    try {
                        this.encryptionContext = null;
                    } catch (Exception e) {
                        log.debug("Error clearing encryption context during emergency cleanup", e);
                    }
                }
            }
        } catch (Exception e) {
            log.error("Failed to perform emergency cleanup", e);
        }
    }

    /**
     * @return the sessionKey
     * @throws CIFSException
     */
    @Override
    public byte[] getSessionKey() throws CIFSException {
        if (this.sessionKey == null) {
            throw new CIFSException("No session key available");
        }
        return this.sessionKey;
    }

    @Override
    public SmbTreeImpl getSmbTree(String share, String service) {
        if (share == null) {
            share = "IPC$";
        }

        synchronized (this.trees) {
            for (SmbTreeImpl t : this.trees) {
                if (t.matches(share, service)) {
                    return t.acquire();
                }
            }
            SmbTreeImpl t = new SmbTreeImpl(this, share, service);
            t.acquire();
            this.trees.add(t);
            return t;
        }
    }

    /**
     * Establish a tree connection with the configured logon share
     *
     * @throws SmbException
     */
    @Override
    public void treeConnectLogon() throws SmbException {
        String logonShare = getContext().getConfig().getLogonShare();
        if (logonShare == null || logonShare.isEmpty()) {
            throw new SmbException("Logon share is not defined");
        }
        try (SmbTreeImpl t = getSmbTree(logonShare, null)) {
            t.treeConnect(null, null);
        } catch (CIFSException e) {
            throw SmbException.wrap(e);
        }
    }

    boolean isSignatureSetupRequired() throws SmbException {
        SMBSigningDigest cur = getDigest();
        if (cur != null) {
            return false;
        }
        if (this.transport.isSigningEnforced()) {
            return true;
        }
        return this.transport.getNegotiateResponse().isSigningNegotiated();
    }

    /**
     * @param digest
     *            the digest to set
     * @throws SmbException
     */
    private void setDigest(SMBSigningDigest digest) throws SmbException {
        if (this.transport.isSMB2()) {
            this.digest = digest;
        } else {
            this.transport.setDigest(digest);
        }
    }

    /**
     * @return the digest
     * @throws SmbException
     */
    public SMBSigningDigest getDigest() throws SmbException {
        if (this.digest != null) {
            return this.digest;
        }
        return this.transport.getDigest();
    }

    /**
     * @param tf
     * @param tdom
     * @param thost
     * @return
     */
    protected boolean matches(CIFSContext tf, String thost, String tdom) {
        return Objects.equals(this.getCredentials(), tf.getCredentials()) && Objects.equals(this.targetHost, thost)
                && Objects.equals(this.targetDomain, tdom);
    }

    <T extends CommonServerMessageBlockResponse> T send(CommonServerMessageBlockRequest request, T response) throws CIFSException {
        return send(request, response, Collections.<RequestParam> emptySet());
    }

    <T extends CommonServerMessageBlockResponse> T send(CommonServerMessageBlockRequest request, T response, Set<RequestParam> params)
            throws CIFSException {
        // Select appropriate transport (multi-channel if available)
        try (SmbTransportImpl trans = selectTransport(request)) {
            if (response != null) {
                response.clearReceived();
                response.setExtendedSecurity(this.extendedSecurity);
            }

            try {
                if (params.contains(RequestParam.NO_TIMEOUT)) {
                    this.expiration = -1;
                } else {
                    this.expiration = System.currentTimeMillis() + this.transportContext.getConfig().getSoTimeout();
                }

                T chainedResponse;
                try {
                    chainedResponse = sessionSetup(request, response);
                } catch (GeneralSecurityException e) {
                    throw new SmbException("Session setup failed", e);
                }

                if (chainedResponse != null && chainedResponse.isReceived()) {
                    return chainedResponse;
                }

                if (request instanceof SmbComTreeConnectAndX tcax) {
                    if (this.netbiosName != null && tcax.getPath().endsWith("\\IPC$")) {
                        /*
                         * Some pipes may require that the hostname in the tree connect
                         * be the netbios name. So if we have the netbios server name
                         * from the NTLMSSP type 2 message, and the share is IPC$, we
                         * assert that the tree connect path uses the netbios hostname.
                         */
                        tcax.setPath("\\\\" + this.netbiosName + "\\IPC$");
                    }
                }

                request.setSessionId(this.sessionId);
                request.setUid(this.uid);

                if (request.getDigest() == null) {
                    request.setDigest(getDigest());
                }

                if (request instanceof RequestWithPath rpath) {
                    ((RequestWithPath) request).setFullUNCPath(getTargetDomain(), getTargetHost(), rpath.getFullUNCPath());
                }

                try {
                    if (log.isTraceEnabled()) {
                        log.trace("Request " + request);
                    }
                    try {
                        response = trans.send(request, response, params);
                    } catch (SmbException e) {
                        // Handle potential multi-channel failure
                        if (isUseMultiChannel() && trans != this.transport) {
                            ChannelInfo channel = channelManager.getChannelForTransport(trans);
                            if (channel != null) {
                                channelManager.handleChannelFailure(channel, e);
                                // Retry with primary transport
                                response = this.transport.send(request, response, params);
                            } else {
                                throw e;
                            }
                        } else {
                            if (e.getNtStatus() != 0xC000035C && e.getNtStatus() != 0xC0000203 || !trans.isSMB2()) {
                                throw e;
                            }
                            if (e.getNtStatus() == 0xC0000203) { // USER_SESSION_DELETED
                                try {
                                    log.warn("Got NT_STATUS_USER_SESSION_DELETED, disconnecting transport");
                                    this.transport.disconnect(true);
                                } catch (IOException e1) {
                                    log.warn("Got NT_STATUS_USER_SESSION_DELETED, disconnected transport with error", e1);
                                }
                            }
                            log.debug("Session expired, trying reauth", e);
                            return reauthenticate(trans, this.targetDomain, request, response, params);
                        }
                    }
                    if (log.isTraceEnabled()) {
                        log.trace("Response " + response);
                    }
                    return response;
                } catch (DfsReferral r) {
                    if (log.isDebugEnabled()) {
                        log.debug("Have referral " + r);
                    }
                    throw r;
                } catch (SmbException se) {
                    if (log.isTraceEnabled()) {
                        log.trace("Send failed", se);
                        log.trace("Request: " + request);
                        log.trace("Response: " + response);
                    }
                    throw se;
                }
            } finally {
                request.setDigest(null);
                this.expiration = System.currentTimeMillis() + this.transportContext.getConfig().getSoTimeout();
            }
        }
    }

    <T extends CommonServerMessageBlock> T sessionSetup(CommonServerMessageBlockRequest chained, T chainedResponse)
            throws CIFSException, GeneralSecurityException {
        try (SmbTransportImpl trans = getTransport()) {
            synchronized (trans) {

                while (!this.connectionState.compareAndSet(0, 1)) {
                    int st = this.connectionState.get();
                    if (st == 2 || st == 3) { // connected or disconnecting
                        return chainedResponse;
                    }
                    try {
                        this.transport.wait();
                    } catch (InterruptedException ie) {
                        throw new SmbException(ie.getMessage(), ie);
                    }
                }

                try {
                    trans.ensureConnected();

                    /*
                     * Session Setup And X Request / Response
                     */

                    if (log.isDebugEnabled()) {
                        log.debug("sessionSetup: " + this.credentials);
                    }

                    /*
                     * We explicitly set uid to 0 here to prevent a new
                     * SMB_COM_SESSION_SETUP_ANDX from having it's uid set to an
                     * old value when the session is re-established. Otherwise a
                     * "The parameter is incorrect" error can occur.
                     */
                    this.uid = 0;

                    if (trans.isSMB2()) {
                        return sessionSetupSMB2(trans, this.targetDomain, (ServerMessageBlock2Request<?>) chained, chainedResponse);
                    }

                    sessionSetupSMB1(trans, this.targetDomain, (ServerMessageBlock) chained, (ServerMessageBlock) chainedResponse);
                    return chainedResponse;
                } catch (Exception se) {
                    log.debug("Session setup failed", se);
                    if (this.connectionState.compareAndSet(1, 0)) {
                        // only try to logoff if we have not completed the session setup, ignore errors from chained
                        // responses
                        logoff(true, true);
                    }
                    throw se;
                } finally {
                    trans.notifyAll();
                }
            }
        }
    }

    /**
     * @param trans
     * @param chain
     * @param andxResponse
     * @throws SmbException
     */
    @SuppressWarnings("unchecked")
    private <T extends CommonServerMessageBlock> T sessionSetupSMB2(SmbTransportImpl trans, final String tdomain,
            ServerMessageBlock2Request<?> chain, T andxResponse) throws CIFSException, GeneralSecurityException {
        final Smb2NegotiateResponse negoResp = (Smb2NegotiateResponse) trans.getNegotiateResponse();
        Smb2SessionSetupRequest request = null;
        Smb2SessionSetupResponse response = null;
        SmbException ex = null;
        SSPContext ctx = null;
        byte[] token = negoResp.getSecurityBlob();
        final int securityMode =
                (negoResp.getSecurityMode() & Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED) != 0 || trans.isSigningEnforced()
                        ? Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED
                        : Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED;
        boolean anonymous = this.credentials.isAnonymous();
        long sessId = 0;

        boolean preauthIntegrity = negoResp.getSelectedDialect().atLeast(DialectVersion.SMB311);
        this.preauthIntegrityHash = preauthIntegrity ? trans.getPreauthIntegrityHash() : null;

        if (this.preauthIntegrityHash != null && log.isDebugEnabled()) {
            log.debug("Initial session preauth hash " + Hexdump.toHexString(this.preauthIntegrityHash));
        }

        while (true) {
            Subject s = this.credentials.getSubject();
            if (ctx == null) {
                ctx = createContext(trans, tdomain, negoResp, !anonymous, s);
            }
            token = createToken(ctx, token, s);

            if (token != null) {
                request = new Smb2SessionSetupRequest(this.getContext(), securityMode, negoResp.getCommonCapabilities(), 0, token);
                // here, messages are rejected with NOT_SUPPORTED if we start signing as soon as we can, wait until
                // session setup complete

                request.setSessionId(sessId);
                request.retainPayload();

                try {
                    response = trans.send(request, null, EnumSet.of(RequestParam.RETAIN_PAYLOAD));
                    sessId = response.getSessionId();
                } catch (SmbAuthException sae) {
                    throw sae;
                } catch (SmbException e) {
                    Smb2SessionSetupResponse sessResponse = request.getResponse();
                    if (e.getNtStatus() == NtStatus.NT_STATUS_INVALID_PARAMETER) {
                        // a relatively large range of samba versions has a bug causing
                        // an invalid parameter error when a SPNEGO MIC is in place and auth fails
                        throw new SmbAuthException("Login failed", e);
                    }
                    if (!sessResponse.isReceived() || sessResponse.isError() || sessResponse.getStatus() != NtStatus.NT_STATUS_SUCCESS
                            && sessResponse.getStatus() != NtStatus.NT_STATUS_MORE_PROCESSING_REQUIRED) {
                        throw e;
                    }
                    ex = e;
                    response = sessResponse;
                }

                if (!this.getConfig().isAllowGuestFallback() && response.isLoggedInAsGuest()
                        && (!this.credentials.isGuest() && !this.credentials.isAnonymous())) {
                    throw new SmbAuthException(NtStatus.NT_STATUS_LOGON_FAILURE);
                }
                if (!this.credentials.isAnonymous() && response.isLoggedInAsGuest()) {
                    anonymous = true;
                }

                if ((response.getSessionFlags() & Smb2SessionSetupResponse.SMB2_SESSION_FLAG_ENCRYPT_DATA) != 0) {
                    // Server requires encryption - create encryption context
                    try {
                        if (log.isDebugEnabled()) {
                            log.debug("Server requires encryption, creating encryption context");
                        }
                        SmbTransportImpl transport = getTransport();
                        this.encryptionContext = transport.createEncryptionContext(this.sessionKey, this.preauthIntegrityHash);
                    } catch (CIFSException e) {
                        log.error("Failed to create encryption context", e);
                        throw new SmbAuthException("Failed to setup required encryption", e);
                    }
                }

                if (preauthIntegrity) {
                    byte[] reqBytes = request.getRawPayload();
                    this.preauthIntegrityHash = trans.calculatePreauthHash(reqBytes, 0, reqBytes.length, this.preauthIntegrityHash);

                    if (response.getStatus() == NtStatus.NT_STATUS_MORE_PROCESSING_REQUIRED) {
                        byte[] respBytes = response.getRawPayload();
                        this.preauthIntegrityHash = trans.calculatePreauthHash(respBytes, 0, respBytes.length, this.preauthIntegrityHash);
                    }
                }

                token = response.getBlob();
            }

            if (ctx.isEstablished()) {
                log.debug("Context is established");
                setNetbiosName(ctx.getNetbiosName());
                byte[] sk = ctx.getSigningKey();
                if (sk != null) {
                    // session key is truncated to 16 bytes, right padded with 0 if shorter
                    byte[] key = new byte[16];
                    System.arraycopy(sk, 0, key, 0, Math.min(16, sk.length));
                    this.sessionKey = key;
                }

                boolean signed = response != null && response.isSigned();
                if (!anonymous && (isSignatureSetupRequired() || signed)) {
                    byte[] signingKey = ctx.getSigningKey();
                    if (signingKey != null && response != null) {
                        if (this.preauthIntegrityHash != null && log.isDebugEnabled()) {
                            log.debug("Final preauth integrity hash " + Hexdump.toHexString(this.preauthIntegrityHash));
                        }
                        Smb2SigningDigest dgst =
                                new Smb2SigningDigest(this.sessionKey, negoResp.getDialectRevision(), this.preauthIntegrityHash);
                        // verify the server signature here, this is not done automatically as we don't set the
                        // request digest
                        // Ignore a missing signature for SMB < 3.0, as
                        // - the specification does not clearly require that (it does for SMB3+)
                        // - there seem to be server implementations (known: EMC Isilon) that do not sign the final
                        // response
                        if (negoResp.getSelectedDialect().atLeast(DialectVersion.SMB300) || response.isSigned()) {
                            response.setDigest(dgst);
                            byte[] payload = response.getRawPayload();
                            if (!response.verifySignature(payload, 0, payload.length)) {
                                throw new SmbException("Signature validation failed");
                            }
                        }
                        setDigest(dgst);
                    } else if (trans.getContext().getConfig().isSigningEnabled()) {
                        throw new SmbException("Signing enabled but no session key available");
                    }
                } else if (log.isDebugEnabled()) {
                    log.debug("No digest setup " + anonymous + " B " + isSignatureSetupRequired());
                }
                setSessionSetup(response);

                // Initialize multi-channel after successful session setup
                initializeMultiChannel();

                // Initialize witness support for fast failover
                initializeWitnessSupport();

                if (ex != null) {
                    throw ex;
                }
                return (T) (response != null ? response.getNextResponse() : null);
            }
        }
    }

    private static byte[] createToken(final SSPContext ctx, final byte[] token, Subject s) throws CIFSException {
        if (s != null) {
            try {
                return Subject.doAs(s,
                        (PrivilegedExceptionAction<byte[]>) () -> ctx.initSecContext(token, 0, token == null ? 0 : token.length));
            } catch (PrivilegedActionException e) {
                if (e.getException() instanceof SmbException) {
                    throw (SmbException) e.getException();
                }
                throw new SmbException("Unexpected exception during context initialization", e);
            }
        }
        return ctx.initSecContext(token, 0, token == null ? 0 : token.length);
    }

    /**
     * @param trans
     * @param tdomain
     * @param negoResp
     * @param ctx
     * @param doSigning
     * @param s
     * @return
     * @throws SmbException
     */
    protected SSPContext createContext(SmbTransportImpl trans, final String tdomain, final Smb2NegotiateResponse negoResp,
            final boolean doSigning, Subject s) throws SmbException {

        String host = getTargetHost();
        if (host == null) {
            host = trans.getRemoteAddress().getHostAddress();
            try {
                host = trans.getRemoteAddress().getHostName();
            } catch (Exception e) {
                log.debug("Failed to resolve host name", e);
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Remote host is " + host);
        }

        if (s == null) {
            return this.credentials.createContext(getContext(), tdomain, host, negoResp.getSecurityBlob(), doSigning);
        }

        try {
            final String hostName = host;
            return Subject.doAs(s, (PrivilegedExceptionAction<SSPContext>) () -> getCredentials().createContext(getContext(), tdomain,
                    hostName, negoResp.getSecurityBlob(), doSigning));
        } catch (PrivilegedActionException e) {
            if (e.getException() instanceof SmbException) {
                throw (SmbException) e.getException();
            }
            throw new SmbException("Unexpected exception during context initialization", e);
        }
    }

    /**
     * @param request
     * @param response
     * @param params
     * @return
     * @throws CIFSException
     */
    @SuppressWarnings("unchecked")
    private <T extends CommonServerMessageBlock> T reauthenticate(SmbTransportImpl trans, final String tdomain,
            CommonServerMessageBlockRequest chain, T andxResponse, Set<RequestParam> params) throws CIFSException {
        SmbException ex = null;
        Smb2SessionSetupResponse response = null;
        Smb2NegotiateResponse negoResp = (Smb2NegotiateResponse) trans.getNegotiateResponse();
        byte[] token = negoResp.getSecurityBlob();
        final int securityMode = negoResp.getSecurityMode();
        boolean anonymous = this.credentials.isAnonymous();
        final boolean doSigning = securityMode != 0 && !anonymous;
        long newSessId = 0;
        long curSessId = this.sessionId;

        synchronized (trans) {
            this.credentials.refresh();
            Subject s = this.credentials.getSubject();
            SSPContext ctx = createContext(trans, tdomain, negoResp, doSigning, s);
            while (true) {
                token = createToken(ctx, token, s);

                if (token != null) {
                    Smb2SessionSetupRequest request = new Smb2SessionSetupRequest(getContext(), negoResp.getSecurityMode(),
                            negoResp.getCommonCapabilities(), curSessId, token);

                    if (chain != null) {
                        request.chain((ServerMessageBlock2) chain);
                    }

                    request.setDigest(this.digest);
                    request.setSessionId(curSessId);

                    try {
                        response = trans.send(request, null, EnumSet.of(RequestParam.RETAIN_PAYLOAD));
                        newSessId = response.getSessionId();

                        if (newSessId != curSessId) {
                            throw new SmbAuthException("Server did not reauthenticate after expiration");
                        }
                    } catch (SmbAuthException sae) {
                        throw sae;
                    } catch (SmbException e) {
                        Smb2SessionSetupResponse sessResponse = request.getResponse();
                        if (!sessResponse.isReceived() || sessResponse.isError() || sessResponse.getStatus() != NtStatus.NT_STATUS_SUCCESS
                                && sessResponse.getStatus() != NtStatus.NT_STATUS_MORE_PROCESSING_REQUIRED) {
                            throw e;
                        }
                        ex = e;
                        response = sessResponse;
                    }

                    if (!this.getConfig().isAllowGuestFallback() && response.isLoggedInAsGuest()
                            && (!this.credentials.isGuest() && !this.credentials.isAnonymous())) {
                        throw new SmbAuthException(NtStatus.NT_STATUS_LOGON_FAILURE);
                    }
                    if (!this.credentials.isAnonymous() && response.isLoggedInAsGuest()) {
                        anonymous = true;
                    }

                    if (request.getDigest() != null) {
                        /* success - install the signing digest */
                        log.debug("Setting digest");
                        setDigest(request.getDigest());
                    }

                    token = response.getBlob();
                }

                if (ex != null) {
                    throw ex;
                }

                if (ctx.isEstablished()) {
                    setSessionSetup(response);
                    @SuppressWarnings("cast")
                    CommonServerMessageBlockResponse cresp = response != null ? response.getNextResponse() : null;
                    if (cresp != null && cresp.isReceived()) {
                        return (T) cresp;
                    }
                    if (chain != null) {
                        return this.transport.send(chain, null, params);
                    }
                    return null;
                }
            }
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public void reauthenticate() throws CIFSException {
        try (SmbTransportImpl trans = getTransport()) {
            reauthenticate(trans, this.targetDomain, null, null, Collections.EMPTY_SET);
        }
    }

    /**
     * @param trans
     * @param andx
     * @param andxResponse
     */
    private void sessionSetupSMB1(final SmbTransportImpl trans, final String tdomain, ServerMessageBlock andx,
            ServerMessageBlock andxResponse) throws CIFSException, GeneralSecurityException {
        SmbException ex = null;
        SmbComSessionSetupAndX request = null;
        SmbComSessionSetupAndXResponse response = null;
        SSPContext ctx = null;
        byte[] token = {};
        int state = 10;
        final SmbComNegotiateResponse negoResp = (SmbComNegotiateResponse) trans.getNegotiateResponse();
        boolean anonymous = this.credentials.isAnonymous();
        do {
            switch (state) {
            case 10: /* NTLM */

                if (trans.hasCapability(SmbConstants.CAP_EXTENDED_SECURITY)) {
                    log.debug("Extended security negotiated");
                    state = 20; /* NTLMSSP */
                    break;
                }
                if (getContext().getConfig().isForceExtendedSecurity()) {
                    throw new SmbException("Server does not supported extended security");
                }

                log.debug("Performing legacy session setup");
                if (!(this.credentials instanceof NtlmPasswordAuthenticator npa)) {
                    throw new SmbAuthException("Incompatible credentials");
                }

                request = new SmbComSessionSetupAndX(this.getContext(), negoResp, andx, getCredentials());
                // if the connection already has a digest set up this needs to be used
                request.setDigest(getDigest());
                response = new SmbComSessionSetupAndXResponse(getContext().getConfig(), andxResponse);
                response.setExtendedSecurity(false);

                /*
                 * Create SMB signature digest if necessary
                 * Only the first SMB_COM_SESSION_SETUP_ANX with non-null or
                 * blank password initializes signing.
                 */
                if (!anonymous && isSignatureSetupRequired()) {
                    if (isExternalAuth(getContext(), npa)) {
                        /*
                         * preauthentication
                         */
                        try (SmbSessionImpl smbSession = trans.getSmbSession(getContext().withDefaultCredentials());
                                SmbTreeImpl t = smbSession.getSmbTree(getContext().getConfig().getLogonShare(), null)) {
                            t.treeConnect(null, null);
                        }
                    } else {
                        log.debug("Initialize signing");
                        byte[] signingKey = npa.getSigningKey(getContext(), negoResp.getServerData().encryptionKey);
                        if (signingKey == null) {
                            throw new SmbException("Need a signature key but the server did not provide one");
                        }
                        request.setDigest(new SMB1SigningDigest(signingKey, false));
                    }
                }

                try {
                    trans.send(request, response);
                } catch (SmbAuthException sae) {
                    throw sae;
                } catch (SmbException se) {
                    ex = se;
                }

                if (!this.getConfig().isAllowGuestFallback() && response.isLoggedInAsGuest()
                        && negoResp.getServerData().security != SmbConstants.SECURITY_SHARE
                        && (!this.credentials.isGuest() && !this.credentials.isAnonymous())) {
                    throw new SmbAuthException(NtStatus.NT_STATUS_LOGON_FAILURE);
                }
                if (!this.credentials.isAnonymous() && response.isLoggedInAsGuest()) {
                    anonymous = true;
                }

                if (ex != null) {
                    throw ex;
                }

                setUid(response.getUid());

                if (request.getDigest() != null) {
                    /* success - install the signing digest */
                    setDigest(request.getDigest());
                } else if (!anonymous && isSignatureSetupRequired()) {
                    throw new SmbException("Signing required but no session key available");
                }

                setSessionSetup(response);
                state = 0;
                break;
            case 20: /* NTLMSSP */
                Subject s = this.credentials.getSubject();
                final boolean doSigning = !anonymous && (negoResp.getNegotiatedFlags2() & SmbConstants.FLAGS2_SECURITY_SIGNATURES) != 0;
                final byte[] curToken = token;
                if (ctx == null) {
                    String host = this.getTargetHost();
                    if (host == null) {
                        host = trans.getRemoteAddress().getHostAddress();
                        try {
                            host = trans.getRemoteAddress().getHostName();
                        } catch (Exception e) {
                            log.debug("Failed to resolve host name", e);
                        }
                    }

                    if (log.isDebugEnabled()) {
                        log.debug("Remote host is " + host);
                    }

                    if (s == null) {
                        ctx = this.credentials.createContext(getContext(), tdomain, host, negoResp.getServerData().encryptionKey,
                                doSigning);
                    } else {
                        try {
                            final String hostName = host;
                            ctx = Subject.doAs(s, (PrivilegedExceptionAction<SSPContext>) () -> getCredentials().createContext(getContext(),
                                    tdomain, hostName, negoResp.getServerData().encryptionKey, doSigning));
                        } catch (PrivilegedActionException e) {
                            if (e.getException() instanceof SmbException) {
                                throw (SmbException) e.getException();
                            }
                            throw new SmbException("Unexpected exception during context initialization", e);
                        }
                    }
                }

                final SSPContext curCtx = ctx;

                if (log.isTraceEnabled()) {
                    log.trace(ctx.toString());
                }

                try {
                    if (s != null) {
                        try {
                            token = Subject.doAs(s, (PrivilegedExceptionAction<byte[]>) () -> curCtx.initSecContext(curToken, 0,
                                    curToken == null ? 0 : curToken.length));
                        } catch (PrivilegedActionException e) {
                            if (e.getException() instanceof SmbException)

                            {
                                throw (SmbException) e.getException();
                            }
                            throw new SmbException("Unexpected exception during context initialization", e);
                        }
                    } else {
                        token = ctx.initSecContext(token, 0, token == null ? 0 : token.length);
                    }
                } catch (SmbException se) {
                    /*
                     * We must close the transport or the server will be expecting a
                     * Type3Message. Otherwise, when we send a Type1Message it will return
                     * "Invalid parameter".
                     */
                    try {
                        log.warn("Exception during SSP authentication", se);
                        trans.disconnect(true);
                    } catch (IOException ioe) {
                        log.debug("Disconnect failed");
                    }
                    setUid(0);
                    throw se;
                }

                if (token != null) {
                    request = new SmbComSessionSetupAndX(this.getContext(), negoResp, null, token);
                    // if the connection already has a digest set up this needs to be used
                    request.setDigest(getDigest());
                    if (doSigning && ctx.isEstablished() && isSignatureSetupRequired()) {
                        byte[] signingKey = ctx.getSigningKey();
                        if (signingKey != null) {
                            request.setDigest(new SMB1SigningDigest(signingKey));
                        }
                        this.sessionKey = signingKey;
                    } else {
                        log.trace("Not yet initializing signing");
                    }

                    response = new SmbComSessionSetupAndXResponse(getContext().getConfig(), null);
                    response.setExtendedSecurity(true);
                    request.setUid(getUid());
                    setUid(0);

                    try {
                        trans.send(request, response);
                    } catch (SmbAuthException sae) {
                        throw sae;
                    } catch (SmbException se) {
                        ex = se;
                        if (se.getNtStatus() == NtStatus.NT_STATUS_INVALID_PARAMETER) {
                            // a relatively large range of samba versions has a bug causing
                            // an invalid parameter error when a SPNEGO MIC is in place and auth fails
                            ex = new SmbAuthException("Login failed", se);
                        }
                        /*
                         * Apparently once a successful NTLMSSP login occurs, the
                         * server will return "Access denied" even if a logoff is
                         * sent. Unfortunately calling disconnect() doesn't always
                         * actually shutdown the connection before other threads
                         * have committed themselves (e.g. InterruptTest example).
                         */
                        try {
                            trans.disconnect(true);
                        } catch (Exception e) {
                            log.debug("Failed to disconnect transport", e);
                        }
                    }

                    if (!getConfig().isAllowGuestFallback() && response.isLoggedInAsGuest()
                            && (!this.credentials.isGuest() && !this.credentials.isAnonymous())) {
                        throw new SmbAuthException(NtStatus.NT_STATUS_LOGON_FAILURE);
                    }
                    if (!this.credentials.isAnonymous() && response.isLoggedInAsGuest()) {
                        anonymous = true;
                    }

                    if (ex != null) {
                        throw ex;
                    }

                    setUid(response.getUid());

                    if (request.getDigest() != null) {
                        /* success - install the signing digest */
                        log.debug("Setting digest");
                        setDigest(request.getDigest());
                    }

                    token = response.getBlob();
                }

                if (ctx.isEstablished()) {
                    log.debug("Context is established");
                    setNetbiosName(ctx.getNetbiosName());
                    this.sessionKey = ctx.getSigningKey();
                    if (request != null && request.getDigest() != null) {
                        /* success - install the signing digest */
                        setDigest(request.getDigest());
                    } else if (!anonymous && isSignatureSetupRequired()) {
                        byte[] signingKey = ctx.getSigningKey();
                        if (signingKey != null && response != null) {
                            setDigest(new SMB1SigningDigest(signingKey, 2));
                        } else if (trans.getContext().getConfig().isSigningEnabled()) {
                            throw new SmbException("Signing required but no session key available");
                        }
                        this.sessionKey = signingKey;
                    }
                    setSessionSetup(response);
                    state = 0;
                    break;
                }
                break;
            default:
                throw new SmbException("Unexpected session setup state: " + state);

            }
        } while (state != 0);
    }

    @SuppressWarnings("deprecation")
    private static boolean isExternalAuth(CIFSContext tc, NtlmPasswordAuthenticator npa) {
        return npa instanceof jcifs.smb.NtlmPasswordAuthentication && ((NtlmPasswordAuthentication) npa).areHashesExternal()
                && tc.getConfig().getDefaultPassword() != null;
    }

    boolean logoff(boolean inError, boolean inUse) {
        boolean wasInUse = false;
        try (SmbTransportImpl trans = getTransport()) {
            synchronized (trans) {
                if (!this.connectionState.compareAndSet(2, 3)) { // not-connected
                    return false;
                }

                if (log.isDebugEnabled()) {
                    log.debug("Logging off session on " + trans);
                }

                this.netbiosName = null;

                synchronized (this.trees) {
                    long us = this.usageCount.get();
                    if ((inUse ? us != 1 : us > 0)) {
                        log.warn("Logging off session while still in use " + this + ":" + this.trees);
                        wasInUse = true;
                    }

                    for (SmbTreeImpl t : this.trees) {
                        try {
                            log.debug("Disconnect tree on logoff");
                            wasInUse |= t.treeDisconnect(inError, false);
                        } catch (Exception e) {
                            log.warn("Failed to disconnect tree " + t, e);
                        }
                    }
                }

                // Cleanup witness client before protocol logoff
                if (witnessClient != null) {
                    try {
                        witnessClient.close();
                        witnessClient = null;
                        witnessEnabled = false;
                        log.debug("Witness client closed on session logoff");
                    } catch (Exception e) {
                        log.warn("Error closing witness client during logoff", e);
                    }
                }

                // Cleanup lease manager
                if (leaseManager != null) {
                    try {
                        leaseManager.shutdown();
                        log.debug("Lease manager shutdown on session logoff");
                    } catch (Exception e) {
                        log.warn("Error shutting down lease manager during logoff", e);
                    }
                }

                // Cleanup persistent handle manager
                if (persistentHandleManager != null) {
                    try {
                        persistentHandleManager.shutdown();
                        log.debug("Persistent handle manager shutdown on session logoff");
                    } catch (Exception e) {
                        log.warn("Error shutting down persistent handle manager during logoff", e);
                    }
                }

                if (!inError && trans.isSMB2()) {
                    Smb2LogoffRequest request = new Smb2LogoffRequest(getConfig());
                    request.setDigest(getDigest());
                    request.setSessionId(this.sessionId);
                    try {
                        this.transport.send(request.ignoreDisconnect(), null);
                    } catch (SmbException se) {
                        log.debug("Smb2LogoffRequest failed", se);
                    }
                } else if (!inError) {
                    boolean shareSecurity = ((SmbComNegotiateResponse) trans.getNegotiateResponse())
                            .getServerData().security == SmbConstants.SECURITY_SHARE;
                    if (!shareSecurity) {
                        SmbComLogoffAndX request = new SmbComLogoffAndX(getConfig(), null);
                        request.setDigest(getDigest());
                        request.setUid(getUid());
                        try {
                            this.transport.send(request, new SmbComBlankResponse(getConfig()));
                        } catch (SmbException se) {
                            log.debug("SmbComLogoffAndX failed", se);
                        }
                        this.uid = 0;
                    }
                }

            }
        } catch (SmbException e) {
            log.warn("Error in logoff", e);
        } finally {
            this.connectionState.set(0);
            this.digest = null;
            this.transport.notifyAll();
        }
        return wasInUse;
    }

    /**
     * Initialize multi-channel support
     */
    private void initializeMultiChannel() {
        try {
            if (channelManager != null) {
                channelManager.initializeMultiChannel();
            }
        } catch (Exception e) {
            log.warn("Failed to initialize multi-channel", e);
        }
    }

    /**
     * Initialize witness support for fast failover
     */
    private void initializeWitnessSupport() {
        Configuration config = getContext().getConfig();

        if (!config.isUseWitness()) {
            return;
        }

        try {
            // Discover witness service
            InetAddress witnessServer = discoverWitnessService();
            if (witnessServer != null) {
                witnessClient = new WitnessClient(witnessServer, getContext());
                witnessEnabled = true;

                log.info("Initialized witness support with server: {}", witnessServer);
            }
        } catch (Exception e) {
            log.warn("Failed to initialize witness support", e);
        }
    }

    /**
     * Discover witness service for the current server
     *
     * @return witness server address or null if not found
     * @throws IOException if discovery fails
     */
    private InetAddress discoverWitnessService() throws IOException {
        // Try the same server first
        InetAddress serverAddress = transport.getRemoteAddress().toInetAddress();

        if (isWitnessServiceAvailable(serverAddress)) {
            return serverAddress;
        }

        // Query for cluster witness service via DNS
        try {
            String clusterName = getClusterName(serverAddress);
            if (clusterName != null) {
                return InetAddress.getByName(clusterName + "-witness");
            }
        } catch (Exception e) {
            log.debug("Failed to discover cluster witness via DNS", e);
        }

        return null; // No witness service found
    }

    /**
     * Check if witness service is available on the given address
     *
     * @param address the address to check
     * @return true if witness service is available
     */
    private boolean isWitnessServiceAvailable(InetAddress address) {
        // RPC endpoint mapper port and connection timeout
        final int RPC_ENDPOINT_PORT = 135;
        final int RPC_CONNECT_TIMEOUT_MS = 5000;

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(address, RPC_ENDPOINT_PORT), RPC_CONNECT_TIMEOUT_MS);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Get cluster name for witness discovery
     *
     * @param serverAddress the server address
     * @return cluster name or null
     */
    private String getClusterName(InetAddress serverAddress) {
        // Simple implementation - could be enhanced with proper cluster discovery
        String hostname = serverAddress.getHostName();
        if (hostname != null && hostname.contains(".")) {
            // Extract potential cluster name from hostname
            String[] parts = hostname.split("\\.");
            if (parts.length > 1) {
                return parts[0]; // Use first part as cluster name
            }
        }
        return null;
    }

    /**
     * Register for witness notifications for a share
     *
     * @param shareName the share name to monitor
     */
    public void registerForWitnessNotifications(String shareName) {
        if (!witnessEnabled || witnessClient == null) {
            return;
        }

        try {
            InetAddress serverAddress = transport.getRemoteAddress().toInetAddress();

            witnessClient.registerForNotifications(shareName, serverAddress, new WitnessNotificationHandler()).thenAccept(registration -> {
                log.info("Registered for witness notifications: share={}, id={}", shareName, registration.getRegistrationId());
            }).exceptionally(error -> {
                log.error("Failed to register for witness notifications", error);
                return null;
            });

        } catch (Exception e) {
            log.error("Error registering for witness notifications", e);
        }
    }

    /**
     * Check if witness support is enabled
     *
     * @return true if witness is enabled
     */
    public boolean isWitnessEnabled() {
        return witnessEnabled;
    }

    /**
     * Handle witness notifications
     */
    private class WitnessNotificationHandler implements WitnessClient.WitnessNotificationListener {
        @Override
        public void onWitnessNotification(WitnessNotification notification) {
            handleWitnessEvent(notification);
        }

        @Override
        public void onRegistrationFailed(WitnessRegistration registration, Exception error) {
            log.error("Witness registration failed: {}", registration.getRegistrationId(), error);
        }

        @Override
        public void onRegistrationExpired(WitnessRegistration registration) {
            log.warn("Witness registration expired: {}", registration.getRegistrationId());
            // Could attempt re-registration here
        }
    }

    /**
     * Handle a witness event
     *
     * @param notification the witness notification
     */
    private void handleWitnessEvent(WitnessNotification notification) {
        log.info("Handling witness event: {} for resource: {}", notification.getEventType(), notification.getResourceName());

        switch (notification.getEventType()) {
        case RESOURCE_CHANGE:
            handleResourceChange(notification);
            break;

        case CLIENT_MOVE:
            handleClientMove(notification);
            break;

        case SHARE_MOVE:
            handleShareMove(notification);
            break;

        case IP_CHANGE:
            handleIPChange(notification);
            break;

        case NODE_UNAVAILABLE:
            handleNodeUnavailable(notification);
            break;

        case NODE_AVAILABLE:
            handleNodeAvailable(notification);
            break;

        default:
            log.debug("Unhandled witness event type: {}", notification.getEventType());
        }
    }

    /**
     * Handle resource change events
     */
    private void handleResourceChange(WitnessNotification notification) {
        // Resource state changed - may need to reconnect
        log.info("Resource change detected for: {}", notification.getResourceName());

        // Schedule reconnection attempt
        scheduleReconnection(getContext().getConfig().getWitnessReconnectDelay());
    }

    /**
     * Handle client move events
     */
    private void handleClientMove(WitnessNotification notification) {
        // Server is asking client to move to different node
        log.info("Client move requested for resource: {}", notification.getResourceName());

        List<WitnessNotification.WitnessIPAddress> newAddresses = notification.getNewIPAddresses();
        if (!newAddresses.isEmpty()) {
            // Attempt to connect to new address
            InetAddress newAddress = newAddresses.get(0).getAddress();
            scheduleAddressChange(newAddress);
        }
    }

    /**
     * Handle share move events
     */
    private void handleShareMove(WitnessNotification notification) {
        // Share moved to different server node
        log.info("Share move detected for: {}", notification.getResourceName());

        // Similar to client move - try new addresses
        handleClientMove(notification);
    }

    /**
     * Handle IP change events
     */
    private void handleIPChange(WitnessNotification notification) {
        // Server IP address changed
        log.info("IP change detected for resource: {}", notification.getResourceName());

        List<WitnessNotification.WitnessIPAddress> newAddresses = notification.getNewIPAddresses();
        if (!newAddresses.isEmpty()) {
            InetAddress newAddress = newAddresses.get(0).getAddress();
            scheduleAddressChange(newAddress);
        }
    }

    /**
     * Handle node unavailable events
     */
    private void handleNodeUnavailable(WitnessNotification notification) {
        log.warn("Node unavailable: {}", notification.getResourceName());
        // Could trigger failover logic here
    }

    /**
     * Handle node available events
     */
    private void handleNodeAvailable(WitnessNotification notification) {
        log.info("Node available: {}", notification.getResourceName());
        // Node is back online - could rebalance connections
    }

    /**
     * Schedule a reconnection attempt
     *
     * @param delayMs delay in milliseconds
     */
    private void scheduleReconnection(long delayMs) {
        CompletableFuture.delayedExecutor(delayMs, TimeUnit.MILLISECONDS).execute(() -> {
            try {
                transport.disconnect(true);
                transport.connect(getConfig().getConnTimeout()); // Reconnect
                log.info("Successfully reconnected after witness notification");
            } catch (Exception e) {
                log.error("Failed to reconnect after witness notification", e);
            }
        });
    }

    /**
     * Schedule an address change
     *
     * @param newAddress the new server address
     */
    private void scheduleAddressChange(InetAddress newAddress) {
        CompletableFuture.runAsync(() -> {
            try {
                // This would require transport architecture changes to support address switching
                // For now, log the event
                log.info("Address change requested to: {} (not implemented)", newAddress);

                // Could implement transport recreation here in the future

            } catch (Exception e) {
                log.error("Failed to handle address change to: {}", newAddress, e);
            }
        });
    }

    /**
     * Check if multi-channel is enabled
     *
     * @return true if multi-channel is enabled
     */
    public boolean isUseMultiChannel() {
        return channelManager != null && channelManager.isUseMultiChannel();
    }

    /**
     * Get the channel manager
     *
     * @return channel manager instance
     */
    public ChannelManager getChannelManager() {
        return channelManager;
    }

    /**
     * Get the lease manager for SMB3 lease support
     *
     * @return lease manager instance
     */
    public LeaseManager getLeaseManager() {
        return leaseManager;
    }

    /**
     * Get the persistent handle manager for SMB3 durable handles
     *
     * @return persistent handle manager instance
     */
    public PersistentHandleManager getPersistentHandleManager() {
        return persistentHandleManager;
    }

    /**
     * Select transport for the given message using multi-channel load balancing
     *
     * @param message message to send
     * @return selected transport
     */
    public SmbTransportImpl selectTransport(CommonServerMessageBlockRequest message) {
        if (isUseMultiChannel()) {
            try {
                ChannelInfo channel = channelManager.selectChannel(message);
                return (SmbTransportImpl) channel.getTransport();
            } catch (Exception e) {
                log.debug("Multi-channel selection failed, using primary transport", e);
            }
        }
        return getTransport();
    }

    @Override
    public String toString() {
        return "SmbSession[credentials=" + this.transportContext.getCredentials() + ",targetHost=" + this.targetHost + ",targetDomain="
                + this.targetDomain + ",uid=" + this.uid + ",connectionState=" + this.connectionState + ",usage=" + this.usageCount.get()
                + "]";
    }

    void setUid(int uid) {
        this.uid = uid;
    }

    void setSessionSetup(Smb2SessionSetupResponse response) {
        this.extendedSecurity = true;
        this.connectionState.set(2);
        this.sessionId = response.getSessionId();
    }

    void setSessionSetup(SmbComSessionSetupAndXResponse response) {
        this.extendedSecurity = response.isExtendedSecurity();
        this.connectionState.set(2);
    }

    void setNetbiosName(String netbiosName) {
        this.netbiosName = netbiosName;
    }

    /**
     * @return the context this session is attached to
     */
    @Override
    public CIFSContext getContext() {
        return this.transport.getContext();
    }

    /**
     * @return the transport this session is attached to
     */
    @Override
    public SmbTransportImpl getTransport() {
        return this.transport.acquire();
    }

    /**
     * @return this session's UID
     */
    public int getUid() {
        return this.uid;
    }

    /**
     * @return this session's expiration time
     */
    public Long getExpiration() {
        return this.expiration > 0 ? this.expiration : null;
    }

    /**
     * @return this session's credentials
     */
    public CredentialsInternal getCredentials() {
        return this.credentials;
    }

    /**
     * @return whether the session is connected
     */
    public boolean isConnected() {
        return !this.transport.isDisconnected() && this.connectionState.get() == 2;
    }

    /**
     * @return whether the session has been lost
     */
    public boolean isFailed() {
        return this.transport.isFailed();
    }

    /**
     * @return whether encryption is enabled for this session
     */
    public boolean isEncryptionEnabled() {
        return this.encryptionContext != null;
    }

    /**
     * @return the encryption context for this session, or null if encryption is not enabled
     */
    public Smb2EncryptionContext getEncryptionContext() {
        return this.encryptionContext;
    }

    /**
     * Encrypt a message using the session's encryption context
     *
     * @param message the message to encrypt
     * @return encrypted message with transform header
     * @throws CIFSException if encryption fails or is not enabled
     */
    public byte[] encryptMessage(byte[] message) throws CIFSException {
        if (this.encryptionContext == null) {
            throw new CIFSException("Encryption not enabled for this session");
        }
        return this.encryptionContext.encryptMessage(message, this.sessionId);
    }

    /**
     * Decrypt a message using the session's encryption context
     *
     * @param encryptedMessage the encrypted message with transform header
     * @return decrypted message
     * @throws CIFSException if decryption fails or encryption is not enabled
     */
    public byte[] decryptMessage(byte[] encryptedMessage) throws CIFSException {
        if (this.encryptionContext == null) {
            throw new CIFSException("Encryption not enabled for this session");
        }
        return this.encryptionContext.decryptMessage(encryptedMessage);
    }

}
