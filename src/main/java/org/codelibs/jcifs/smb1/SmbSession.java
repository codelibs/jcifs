/* org.codelibs.jcifs.smb smb client library in Java
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

package org.codelibs.jcifs.smb1;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Enumeration;
import java.util.Vector;

import org.codelibs.jcifs.smb1.netbios.NbtAddress;
import org.codelibs.jcifs.smb1.util.LogStream;

/**
 * The SmbSession class represents an SMB session established with a server.
 * It provides methods for authentication and session management.
 */
public final class SmbSession {

    private static final String LOGON_SHARE = Config.getProperty("jcifs.client.logonShare", null);
    private static final int LOOKUP_RESP_LIMIT = Config.getInt("jcifs.netbios.lookupRespLimit", 3);
    private static final String DOMAIN = Config.getProperty("jcifs.client.domain", null);
    private static final String USERNAME = Config.getProperty("jcifs.client.username", null);
    private static final int CACHE_POLICY = Config.getInt("jcifs.netbios.cachePolicy", 60 * 10) * 60; /* 10 hours */

    static NbtAddress[] dc_list = null;
    static long dc_list_expiration;
    static int dc_list_counter;

    private static NtlmChallenge interrogate(final NbtAddress addr) throws SmbException {
        final UniAddress dc = new UniAddress(addr);
        final SmbTransport trans = SmbTransport.getSmbTransport(dc, 0);
        if (USERNAME == null) {
            trans.connect();
            if (LogStream.level >= 3) {
                SmbTransport.log.println("""
                        Default credentials (jcifs.client.username/password)\
                         not specified. SMB signing may not work propertly.\
                          Skipping DC interrogation.""");
            }
        } else {
            final SmbSession ssn = trans.getSmbSession(NtlmPasswordAuthentication.DEFAULT);
            ssn.getSmbTree(LOGON_SHARE, null).treeConnect(null, null);
        }
        return new NtlmChallenge(trans.server.encryptionKey, dc);
    }

    /**
     * Retrieves an NTLM challenge from a domain controller for the configured domain.
     *
     * @return the NTLM challenge from the domain controller
     * @throws SmbException if an SMB error occurs
     * @throws UnknownHostException if the domain controller cannot be resolved
     */
    public static NtlmChallenge getChallengeForDomain() throws SmbException, UnknownHostException {
        if (DOMAIN == null) {
            throw new SmbException("A domain was not specified");
        }
        synchronized (DOMAIN) {
            final long now = System.currentTimeMillis();
            int retry = 1;

            do {
                if (dc_list_expiration < now) {
                    final NbtAddress[] list = NbtAddress.getAllByName(DOMAIN, 0x1C, null, null);
                    dc_list_expiration = now + CACHE_POLICY * 1000L;
                    if (list != null && list.length > 0) {
                        dc_list = list;
                    } else { /* keep using the old list */
                        dc_list_expiration = now + 1000 * 60 * 15; /* 15 min */
                        if (LogStream.level >= 2) {
                            SmbTransport.log.println("Failed to retrieve DC list from WINS");
                        }
                    }
                }

                final int max = Math.min(dc_list.length, LOOKUP_RESP_LIMIT);
                for (int j = 0; j < max; j++) {
                    final int i = dc_list_counter++ % max;
                    if (dc_list[i] != null) {
                        try {
                            return interrogate(dc_list[i]);
                        } catch (final SmbException se) {
                            if (LogStream.level >= 2) {
                                SmbTransport.log.println("Failed validate DC: " + dc_list[i]);
                                if (LogStream.level > 2) {
                                    se.printStackTrace(SmbTransport.log);
                                }
                            }
                        }
                        dc_list[i] = null;
                    }
                }

                /* No DCs found, for retieval of list by expiring it and retry.
                 */
                dc_list_expiration = 0;
            } while (retry-- > 0);

            dc_list_expiration = now + 1000 * 60 * 15; /* 15 min */
        }

        throw new UnknownHostException("Failed to negotiate with a suitable domain controller for " + DOMAIN);
    }

    /**
     * Retrieves the NTLM challenge from the specified domain controller.
     *
     * @param dc the domain controller address
     * @return the NTLM challenge bytes
     * @throws SmbException if an SMB error occurs
     * @throws UnknownHostException if the host cannot be resolved
     */
    public static byte[] getChallenge(final UniAddress dc) throws SmbException, UnknownHostException {
        return getChallenge(dc, 0);
    }

    /**
     * Retrieves the NTLM challenge from the specified domain controller using the specified port.
     *
     * @param dc the domain controller address
     * @param port the port to connect to
     * @return the NTLM challenge bytes
     * @throws SmbException if an SMB error occurs
     * @throws UnknownHostException if the host cannot be resolved
     */
    public static byte[] getChallenge(final UniAddress dc, final int port) throws SmbException, UnknownHostException {
        final SmbTransport trans = SmbTransport.getSmbTransport(dc, port);
        trans.connect();
        return trans.server.encryptionKey;
    }

    /**
     * Authenticate arbitrary credentials represented by the
     * <code>NtlmPasswordAuthentication</code> object against the domain controller
     * specified by the <code>UniAddress</code> parameter. If the credentials are
     * not accepted, an <code>SmbAuthException</code> will be thrown. If an error
     * occurs an <code>SmbSystemException</code> will be thrown. If the credentials are
     * valid, the method will return without throwing an exception. See the
     * last <a href="../../../faq.html">FAQ</a> question.
     * <p>
     * See also the <code>org.codelibs.jcifs.smb1.smb1.client.logonShare</code> property.
     *
     * @param dc the domain controller to authenticate against
     * @param auth the authentication credentials
     * @throws SmbException if authentication fails or an SMB error occurs
     */
    public static void logon(final UniAddress dc, final NtlmPasswordAuthentication auth) throws SmbException {
        logon(dc, 0, auth);
    }

    /**
     * Authenticate arbitrary credentials against the specified domain controller using the specified port.
     *
     * @param dc the domain controller to authenticate against
     * @param port the port to connect to
     * @param auth the authentication credentials
     * @throws SmbException if authentication fails or an SMB error occurs
     */
    public static void logon(final UniAddress dc, final int port, final NtlmPasswordAuthentication auth) throws SmbException {
        final SmbTree tree = SmbTransport.getSmbTransport(dc, port).getSmbSession(auth).getSmbTree(LOGON_SHARE, null);
        if (LOGON_SHARE == null) {
            tree.treeConnect(null, null);
        } else {
            final Trans2FindFirst2 req = new Trans2FindFirst2("\\", "*", SmbFile.ATTR_DIRECTORY);
            final Trans2FindFirst2Response resp = new Trans2FindFirst2Response();
            tree.send(req, resp);
        }
    }

    /* 0 - not connected
     * 1 - connecting
     * 2 - connected
     * 3 - disconnecting
     */
    int connectionState;
    int uid;
    Vector trees;
    // Transport parameters allows trans to be removed from CONNECTIONS
    private final UniAddress address;
    private final int port, localPort;
    private final InetAddress localAddr;

    SmbTransport transport = null;
    NtlmPasswordAuthentication auth;
    long expiration;
    String netbiosName = null;

    SmbSession(final UniAddress address, final int port, final InetAddress localAddr, final int localPort,
            final NtlmPasswordAuthentication auth) {
        this.address = address;
        this.port = port;
        this.localAddr = localAddr;
        this.localPort = localPort;
        this.auth = auth;
        trees = new Vector();
        connectionState = 0;
    }

    synchronized SmbTree getSmbTree(String share, final String service) {
        SmbTree t;

        if (share == null) {
            share = "IPC$";
        }
        for (final Enumeration e = trees.elements(); e.hasMoreElements();) {
            t = (SmbTree) e.nextElement();
            if (t.matches(share, service)) {
                return t;
            }
        }
        t = new SmbTree(this, share, service);
        trees.addElement(t);
        return t;
    }

    boolean matches(final NtlmPasswordAuthentication auth) {
        return this.auth == auth || this.auth.equals(auth);
    }

    synchronized SmbTransport transport() {
        if (transport == null) {
            transport = SmbTransport.getSmbTransport(address, port, localAddr, localPort, null);
        }
        return transport;
    }

    void send(final ServerMessageBlock request, final ServerMessageBlock response) throws SmbException {
        synchronized (transport()) {
            if (response != null) {
                response.received = false;
            }

            expiration = System.currentTimeMillis() + SmbConstants.SO_TIMEOUT;
            sessionSetup(request, response);
            if (response != null && response.received) {
                return;
            }

            if (request instanceof final SmbComTreeConnectAndX tcax) {
                if (netbiosName != null && tcax.path.endsWith("\\IPC$")) {
                    /* Some pipes may require that the hostname in the tree connect
                     * be the netbios name. So if we have the netbios server name
                     * from the NTLMSSP type 2 message, and the share is IPC$, we
                     * assert that the tree connect path uses the netbios hostname.
                     */
                    tcax.path = "\\\\" + netbiosName + "\\IPC$";
                }
            }

            request.uid = uid;
            request.auth = auth;
            try {
                transport.send(request, response);
            } catch (final SmbException se) {
                if (request instanceof SmbComTreeConnectAndX) {
                    logoff(true);
                }
                request.digest = null;
                throw se;
            }
        }
    }

    void sessionSetup(final ServerMessageBlock andx, final ServerMessageBlock andxResponse) throws SmbException {
        synchronized (transport()) {
            NtlmContext nctx = null;
            SmbException ex = null;
            SmbComSessionSetupAndX request;
            SmbComSessionSetupAndXResponse response;
            byte[] token = {};
            int state = 10;

            while (connectionState != 0) {
                if (connectionState == 2 || connectionState == 3) { // connected or disconnecting
                    return;
                }
                try {
                    transport.wait();
                } catch (final InterruptedException ie) {
                    throw new SmbException(ie.getMessage(), ie);
                }
            }
            connectionState = 1; // trying ...

            try {
                transport.connect();

                /*
                 * Session Setup And X Request / Response
                 */

                if (LogStream.level >= 4) {
                    SmbTransport.log.println("sessionSetup: accountName=" + auth.username + ",primaryDomain=" + auth.domain);
                }

                /* We explicitly set uid to 0 here to prevent a new
                 * SMB_COM_SESSION_SETUP_ANDX from having it's uid set to an
                 * old value when the session is re-established. Otherwise a
                 * "The parameter is incorrect" error can occur.
                 */
                uid = 0;

                do {
                    switch (state) {
                    case 10: /* NTLM */
                        if (auth != NtlmPasswordAuthentication.ANONYMOUS && transport.hasCapability(SmbConstants.CAP_EXTENDED_SECURITY)) {
                            state = 20; /* NTLMSSP */
                            break;
                        }

                        request = new SmbComSessionSetupAndX(this, andx, auth);
                        response = new SmbComSessionSetupAndXResponse(andxResponse);

                        /* Create SMB signature digest if necessary
                         * Only the first SMB_COM_SESSION_SETUP_ANX with non-null or
                         * blank password initializes signing.
                         */
                        if (transport.isSignatureSetupRequired(auth)) {
                            if (auth.hashesExternal && NtlmPasswordAuthentication.DEFAULT_PASSWORD != NtlmPasswordAuthentication.BLANK) {
                                /* preauthentication
                                 */
                                transport.getSmbSession(NtlmPasswordAuthentication.DEFAULT)
                                        .getSmbTree(LOGON_SHARE, null)
                                        .treeConnect(null, null);
                            } else {
                                final byte[] signingKey = auth.getSigningKey(transport.server.encryptionKey);
                                request.digest = new SigningDigest(signingKey, false);
                            }
                        }

                        request.auth = auth;

                        try {
                            transport.send(request, response);
                        } catch (final SmbAuthException sae) {
                            throw sae;
                        } catch (final SmbException se) {
                            ex = se;
                        }

                        if (response.isLoggedInAsGuest && !"GUEST".equalsIgnoreCase(auth.username)
                                && transport.server.security != SmbConstants.SECURITY_SHARE
                                && auth != NtlmPasswordAuthentication.ANONYMOUS) {
                            throw new SmbAuthException(NtStatus.NT_STATUS_LOGON_FAILURE);
                        }

                        if (ex != null) {
                            throw ex;
                        }

                        uid = response.uid;

                        if (request.digest != null) {
                            /* success - install the signing digest */
                            transport.digest = request.digest;
                        }

                        connectionState = 2;

                        state = 0;

                        break;
                    case 20:
                        if (nctx == null) {
                            final boolean doSigning = (transport.flags2 & SmbConstants.FLAGS2_SECURITY_SIGNATURES) != 0;
                            nctx = new NtlmContext(auth, doSigning);
                        }

                        if (LogStream.level >= 4) {
                            SmbTransport.log.println(nctx);
                        }

                        if (nctx.isEstablished()) {

                            netbiosName = nctx.getNetbiosName();

                            connectionState = 2;

                            state = 0;
                            break;
                        }

                        try {
                            token = nctx.initSecContext(token, 0, token.length);
                        } catch (final SmbException se) {
                            /* We must close the transport or the server will be expecting a
                             * Type3Message. Otherwise, when we send a Type1Message it will return
                             * "Invalid parameter".
                             */
                            try {
                                transport.disconnect(true);
                            } catch (final IOException ioe) {}
                            uid = 0;
                            throw se;
                        }

                        if (token != null) {
                            request = new SmbComSessionSetupAndX(this, null, token);
                            response = new SmbComSessionSetupAndXResponse(null);

                            if (transport.isSignatureSetupRequired(auth)) {
                                final byte[] signingKey = nctx.getSigningKey();
                                if (signingKey != null) {
                                    request.digest = new SigningDigest(signingKey, true);
                                }
                            }

                            request.uid = uid;
                            uid = 0;

                            try {
                                transport.send(request, response);
                            } catch (final SmbAuthException sae) {
                                throw sae;
                            } catch (final SmbException se) {
                                ex = se;
                                /* Apparently once a successfull NTLMSSP login occurs, the
                                 * server will return "Access denied" even if a logoff is
                                 * sent. Unfortunately calling disconnect() doesn't always
                                 * actually shutdown the connection before other threads
                                 * have committed themselves (e.g. InterruptTest example).
                                 */
                                try {
                                    transport.disconnect(true);
                                } catch (final Exception e) {}
                            }

                            if (response.isLoggedInAsGuest && !"GUEST".equalsIgnoreCase(auth.username)) {
                                throw new SmbAuthException(NtStatus.NT_STATUS_LOGON_FAILURE);
                            }

                            if (ex != null) {
                                throw ex;
                            }

                            uid = response.uid;

                            if (request.digest != null) {
                                /* success - install the signing digest */
                                transport.digest = request.digest;
                            }

                            token = response.blob;
                        }

                        break;
                    default:
                        throw new SmbException("Unexpected session setup state: " + state);
                    }
                } while (state != 0);
            } catch (final SmbException se) {
                logoff(true);
                connectionState = 0;
                throw se;
            } finally {
                transport.notifyAll();
            }
        }
    }

    void logoff(final boolean inError) {
        synchronized (transport()) {

            if (connectionState != 2) { // not-connected
                return;
            }
            connectionState = 3; // disconnecting

            netbiosName = null;

            for (final Enumeration e = trees.elements(); e.hasMoreElements();) {
                final SmbTree t = (SmbTree) e.nextElement();
                t.treeDisconnect(inError);
            }

            if (!inError && transport.server.security != SmbConstants.SECURITY_SHARE) {
                /*
                 * Logoff And X Request / Response
                 */

                final SmbComLogoffAndX request = new SmbComLogoffAndX(null);
                request.uid = uid;
                try {
                    transport.send(request, null);
                } catch (final SmbException se) {}
                uid = 0;
            }

            connectionState = 0;
            transport.notifyAll();
        }
    }

    @Override
    public String toString() {
        return "SmbSession[accountName=" + auth.username + ",primaryDomain=" + auth.domain + ",uid=" + uid + ",connectionState="
                + connectionState + "]";
    }
}
