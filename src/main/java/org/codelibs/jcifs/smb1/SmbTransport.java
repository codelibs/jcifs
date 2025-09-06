/*
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

package org.codelibs.jcifs.smb1;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NoRouteToHostException;
import java.net.Socket;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.ListIterator;

import org.codelibs.jcifs.smb1.netbios.Name;
import org.codelibs.jcifs.smb1.netbios.NbtAddress;
import org.codelibs.jcifs.smb1.netbios.NbtException;
import org.codelibs.jcifs.smb1.netbios.SessionRequestPacket;
import org.codelibs.jcifs.smb1.netbios.SessionServicePacket;
import org.codelibs.jcifs.smb1.util.Encdec;
import org.codelibs.jcifs.smb1.util.Hexdump;
import org.codelibs.jcifs.smb1.util.LogStream;
import org.codelibs.jcifs.smb1.util.transport.Request;
import org.codelibs.jcifs.smb1.util.transport.Response;
import org.codelibs.jcifs.smb1.util.transport.Transport;
import org.codelibs.jcifs.smb1.util.transport.TransportException;

/**
 * Legacy SMB transport implementation for SMB1 protocol communication.
 * Handles the low-level transport layer for SMB1 protocol messages.
 */
public class SmbTransport extends Transport implements SmbConstants {

    static final byte[] BUF = new byte[0xFFFF];
    static final SmbComNegotiate NEGOTIATE_REQUEST = new SmbComNegotiate();
    static LogStream log = LogStream.getInstance();
    static HashMap dfsRoots = null;

    static synchronized SmbTransport getSmbTransport(final UniAddress address, final int port) {
        return getSmbTransport(address, port, LADDR, LPORT, null);
    }

    static synchronized SmbTransport getSmbTransport(final UniAddress address, final int port, final InetAddress localAddr,
            final int localPort, final String hostName) {
        SmbTransport conn;

        synchronized (CONNECTIONS) {
            if (SSN_LIMIT != 1) {
                final ListIterator iter = CONNECTIONS.listIterator();
                while (iter.hasNext()) {
                    conn = (SmbTransport) iter.next();
                    if (conn.matches(address, port, localAddr, localPort, hostName)
                            && (SSN_LIMIT == 0 || conn.sessions.size() < SSN_LIMIT)) {
                        return conn;
                    }
                }
            }

            conn = new SmbTransport(address, port, localAddr, localPort);
            CONNECTIONS.add(0, conn);
        }

        return conn;
    }

    class ServerData {
        byte flags;
        int flags2;
        int maxMpxCount;
        int maxBufferSize;
        int sessionKey;
        int capabilities;
        String oemDomainName;
        int securityMode;
        int security;
        boolean encryptedPasswords;
        boolean signaturesEnabled;
        boolean signaturesRequired;
        int maxNumberVcs;
        int maxRawSize;
        long serverTime;
        int serverTimeZone;
        int encryptionKeyLength;
        byte[] encryptionKey;
        byte[] guid;
    }

    InetAddress localAddr;
    int localPort;
    UniAddress address;
    Socket socket;
    int port, mid;
    OutputStream out;
    InputStream in;
    byte[] sbuf = new byte[512]; /* small local buffer */
    SmbComBlankResponse key = new SmbComBlankResponse();
    long sessionExpiration = System.currentTimeMillis() + SO_TIMEOUT;
    LinkedList referrals = new LinkedList();
    SigningDigest digest = null;
    LinkedList sessions = new LinkedList();
    ServerData server = new ServerData();
    /* Negotiated values */
    int flags2 = FLAGS2;
    int maxMpxCount = MAX_MPX_COUNT;
    int snd_buf_size = SND_BUF_SIZE;
    int rcv_buf_size = RCV_BUF_SIZE;
    int capabilities = CAPABILITIES;
    int sessionKey = 0x00000000;
    boolean useUnicode = USE_UNICODE;
    String tconHostName = null;

    SmbTransport(final UniAddress address, final int port, final InetAddress localAddr, final int localPort) {
        this.address = address;
        this.port = port;
        this.localAddr = localAddr;
        this.localPort = localPort;
    }

    synchronized SmbSession getSmbSession() {
        return getSmbSession(new NtlmPasswordAuthentication(null, null, null));
    }

    synchronized SmbSession getSmbSession(final NtlmPasswordAuthentication auth) {
        SmbSession ssn;
        long now;

        ListIterator iter = sessions.listIterator();
        while (iter.hasNext()) {
            ssn = (SmbSession) iter.next();
            if (ssn.matches(auth)) {
                ssn.auth = auth;
                return ssn;
            }
        }

        /* logoff old sessions */
        if (SO_TIMEOUT > 0 && sessionExpiration < (now = System.currentTimeMillis())) {
            sessionExpiration = now + SO_TIMEOUT;
            iter = sessions.listIterator();
            while (iter.hasNext()) {
                ssn = (SmbSession) iter.next();
                if (ssn.expiration < now) {
                    ssn.logoff(false);
                }
            }
        }

        ssn = new SmbSession(address, port, localAddr, localPort, auth);
        ssn.transport = this;
        sessions.add(ssn);

        return ssn;
    }

    boolean matches(final UniAddress address, final int port, final InetAddress localAddr, final int localPort, String hostName) {
        if (hostName == null) {
            hostName = address.getHostName();
        }
        return (this.tconHostName == null || hostName.equalsIgnoreCase(this.tconHostName)) && address.equals(this.address)
                && (port == 0 || port == this.port ||
                /* port 139 is ok if 445 was requested */
                        port == 445 && this.port == 139)
                && (localAddr == this.localAddr || localAddr != null && localAddr.equals(this.localAddr)) && localPort == this.localPort;
    }

    boolean hasCapability(final int cap) throws SmbException {
        try {
            connect(RESPONSE_TIMEOUT);
        } catch (final IOException ioe) {
            throw new SmbException(ioe.getMessage(), ioe);
        }
        return (capabilities & cap) == cap;
    }

    boolean isSignatureSetupRequired(final NtlmPasswordAuthentication auth) {
        return (flags2 & SmbConstants.FLAGS2_SECURITY_SIGNATURES) != 0 && digest == null && auth != NtlmPasswordAuthentication.NULL
                && !NtlmPasswordAuthentication.NULL.equals(auth);
    }

    void ssn139() throws IOException {
        final Name calledName = new Name(address.firstCalledName(), 0x20, null);
        do {
            /* These Socket constructors attempt to connect before SO_TIMEOUT can be applied
            if (localAddr == null) {
                socket = new Socket( address.getHostAddress(), 139 );
            } else {
                socket = new Socket( address.getHostAddress(), 139, localAddr, localPort );
            }
            socket.setSoTimeout( SO_TIMEOUT );
            */

            socket = new Socket();
            if (localAddr != null) {
                socket.bind(new InetSocketAddress(localAddr, localPort));
            }
            socket.connect(new InetSocketAddress(address.getHostAddress(), 139), CONN_TIMEOUT);
            socket.setSoTimeout(SO_TIMEOUT);

            out = socket.getOutputStream();
            in = socket.getInputStream();

            final SessionServicePacket ssp = new SessionRequestPacket(calledName, NbtAddress.getLocalName());
            out.write(sbuf, 0, ssp.writeWireFormat(sbuf, 0));
            if (readn(in, sbuf, 0, 4) < 4) {
                try {
                    socket.close();
                } catch (final IOException ioe) {}
                throw new SmbException("EOF during NetBIOS session request");
            }
            switch (sbuf[0] & 0xFF) {
            case SessionServicePacket.POSITIVE_SESSION_RESPONSE:
                if (LogStream.level >= 4) {
                    log.println("session established ok with " + address);
                }
                return;
            case SessionServicePacket.NEGATIVE_SESSION_RESPONSE:
                final int errorCode = in.read() & 0xFF;
                switch (errorCode) {
                case NbtException.CALLED_NOT_PRESENT:
                case NbtException.NOT_LISTENING_CALLED:
                    socket.close();
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
        } while ((calledName.name = address.nextCalledName()) != null);

        throw new IOException("Failed to establish session with " + address);
    }

    private void negotiate(int port, final ServerMessageBlock resp) throws IOException {
        /* We cannot use Transport.sendrecv() yet because
         * the Transport thread is not setup until doConnect()
         * returns and we want to supress all communication
         * until we have properly negotiated.
         */
        synchronized (sbuf) {
            if (port == 139) {
                ssn139();
            } else {
                if (port == 0) {
                    port = DEFAULT_PORT; // 445
                }
                /* These Socket constructors attempt to connect before SO_TIMEOUT can be applied
                if (localAddr == null) {
                    socket = new Socket( address.getHostAddress(), port );
                } else {
                    socket = new Socket( address.getHostAddress(), port, localAddr, localPort );
                }
                socket.setSoTimeout( SO_TIMEOUT );
                */
                socket = new Socket();
                if (localAddr != null) {
                    socket.bind(new InetSocketAddress(localAddr, localPort));
                }
                socket.connect(new InetSocketAddress(address.getHostAddress(), port), CONN_TIMEOUT);
                socket.setSoTimeout(SO_TIMEOUT);

                out = socket.getOutputStream();
                in = socket.getInputStream();
            }

            if (++mid == 32000) {
                mid = 1;
            }
            NEGOTIATE_REQUEST.mid = mid;
            final int n = NEGOTIATE_REQUEST.encode(sbuf, 4);
            Encdec.enc_uint32be(n & 0xFFFF, sbuf, 0); /* 4 byte ssn msg header */

            if (LogStream.level >= 4) {
                log.println(NEGOTIATE_REQUEST);
                if (LogStream.level >= 6) {
                    Hexdump.hexdump(log, sbuf, 4, n);
                }
            }

            out.write(sbuf, 0, 4 + n);
            out.flush();
            /* Note the Transport thread isn't running yet so we can
             * read from the socket here.
             */
            if (peekKey() == null) { /* try to read header */
                throw new IOException("transport closed in negotiate");
            }
            final int size = Encdec.dec_uint16be(sbuf, 2) & 0xFFFF;
            if (size < 33 || 4 + size > sbuf.length) {
                throw new IOException("Invalid payload size: " + size);
            }
            readn(in, sbuf, 4 + 32, size - 32);
            resp.decode(sbuf, 4);

            if (LogStream.level >= 4) {
                log.println(resp);
                if (LogStream.level >= 6) {
                    Hexdump.hexdump(log, sbuf, 4, n);
                }
            }
        }
    }

    /**
     * Establishes a connection to the SMB server.
     *
     * @throws SmbException if the connection fails
     */
    public void connect() throws SmbException {
        try {
            super.connect(RESPONSE_TIMEOUT);
        } catch (final TransportException te) {
            throw new SmbException("Failed to connect: " + address, te);
        }
    }

    @Override
    protected void doConnect() throws IOException {
        /*
         * Negotiate Protocol Request / Response
         */

        final SmbComNegotiateResponse resp = new SmbComNegotiateResponse(server);
        try {
            negotiate(port, resp);
        } catch (final ConnectException | NoRouteToHostException nr) {
            // Try an alternate port if there was an issue communicating to the server
            // Only set the alternate port to the port property if it was successful
            final int altPort = port == 0 || port == DEFAULT_PORT ? 139 : DEFAULT_PORT;
            negotiate(altPort, resp);
            port = altPort;
        }

        if (resp.dialectIndex > 10) {
            throw new SmbException("This client does not support the negotiated dialect.");
        }
        if ((server.capabilities & CAP_EXTENDED_SECURITY) != CAP_EXTENDED_SECURITY && server.encryptionKeyLength != 8
                && LM_COMPATIBILITY == 0) {
            throw new SmbException("Unexpected encryption key length: " + server.encryptionKeyLength);
        }

        /* Adjust negotiated values */

        tconHostName = address.getHostName();
        if (server.signaturesRequired || server.signaturesEnabled && SIGNPREF) {
            flags2 |= SmbConstants.FLAGS2_SECURITY_SIGNATURES;
        } else {
            flags2 &= 0xFFFF ^ SmbConstants.FLAGS2_SECURITY_SIGNATURES;
        }
        maxMpxCount = Math.min(maxMpxCount, server.maxMpxCount);
        if (maxMpxCount < 1) {
            maxMpxCount = 1;
        }
        snd_buf_size = Math.min(snd_buf_size, server.maxBufferSize);
        capabilities &= server.capabilities;
        if ((server.capabilities & CAP_EXTENDED_SECURITY) == CAP_EXTENDED_SECURITY) {
            capabilities |= CAP_EXTENDED_SECURITY; // & doesn't copy high bit
        }

        if ((capabilities & SmbConstants.CAP_UNICODE) == 0) {
            // server doesn't want unicode
            if (FORCE_UNICODE) {
                capabilities |= SmbConstants.CAP_UNICODE;
            } else {
                useUnicode = false;
                flags2 &= 0xFFFF ^ SmbConstants.FLAGS2_UNICODE;
            }
        }
    }

    @Override
    protected void doDisconnect(final boolean hard) throws IOException {
        final ListIterator iter = sessions.listIterator();
        try {
            while (iter.hasNext()) {
                final SmbSession ssn = (SmbSession) iter.next();
                ssn.logoff(hard);
            }
            socket.shutdownOutput();
            out.close();
            in.close();
            socket.close();
        } finally {
            digest = null;
            socket = null;
            tconHostName = null;
        }
    }

    @Override
    protected void makeKey(final Request request) throws IOException {
        /* The request *is* the key */
        if (++mid == 32000) {
            mid = 1;
        }
        ((ServerMessageBlock) request).mid = mid;
    }

    @Override
    protected Request peekKey() throws IOException {
        int n;
        do {
            if ((n = readn(in, sbuf, 0, 4)) < 4) {
                return null;
            }
        } while (sbuf[0] == (byte) 0x85); /* Dodge NetBIOS keep-alive */
        n = readn(in, sbuf, 4, 32);
        /* read smb header */
        if (n < 32) {
            return null;
        }
        if (LogStream.level >= 4) {
            log.println("New data read: " + this);
            org.codelibs.jcifs.smb1.util.Hexdump.hexdump(log, sbuf, 4, 32);
        }

        for (;;) {
            /* 01234567
             * 00SSFSMB
             * 0 - 0's
             * S - size of payload
             * FSMB - 0xFF SMB magic #
             */

            if (sbuf[0] == (byte) 0x00 && sbuf[1] == (byte) 0x00 && sbuf[4] == (byte) 0xFF && sbuf[5] == (byte) 'S' && sbuf[6] == (byte) 'M'
                    && sbuf[7] == (byte) 'B') {
                break; /* all good */
            }
            /* out of phase maybe? */
            /* inch forward 1 byte and try again */
            for (int i = 0; i < 35; i++) {
                sbuf[i] = sbuf[i + 1];
            }
            int b;
            if ((b = in.read()) == -1) {
                return null;
            }
            sbuf[35] = (byte) b;
        }

        key.mid = Encdec.dec_uint16le(sbuf, 34) & 0xFFFF;

        /* Unless key returned is null or invalid Transport.loop() always
         * calls doRecv() after and no one else but the transport thread
         * should call doRecv(). Therefore it is ok to expect that the data
         * in sbuf will be preserved for copying into BUF in doRecv().
         */

        return key;
    }

    @Override
    protected void doSend(final Request request) throws IOException {
        synchronized (BUF) {
            ServerMessageBlock smb = (ServerMessageBlock) request;
            final int n = smb.encode(BUF, 4);
            Encdec.enc_uint32be(n & 0xFFFF, BUF, 0); /* 4 byte session message header */
            if (LogStream.level >= 4) {
                do {
                    log.println(smb);
                } while (smb instanceof AndXServerMessageBlock && (smb = ((AndXServerMessageBlock) smb).andx) != null);
                if (LogStream.level >= 6) {
                    Hexdump.hexdump(log, BUF, 4, n);
                }
            }
            /* For some reason this can sometimes get broken up into another
             * "NBSS Continuation Message" frame according to WireShark
             */
            out.write(BUF, 0, 4 + n);
        }
    }

    /**
     * Internal method to send a request to the server.
     *
     * @param request the request to send
     * @throws IOException if an I/O error occurs
     */
    protected void doSend0(final Request request) throws IOException {
        try {
            doSend(request);
        } catch (final IOException ioe) {
            if (LogStream.level > 2) {
                ioe.printStackTrace(log);
            }
            try {
                disconnect(true);
            } catch (final IOException ioe2) {
                ioe2.printStackTrace(log);
            }
            throw ioe;
        }
    }

    @Override
    protected void doRecv(final Response response) throws IOException {
        final ServerMessageBlock resp = (ServerMessageBlock) response;
        resp.useUnicode = useUnicode;
        resp.extendedSecurity = (capabilities & CAP_EXTENDED_SECURITY) == CAP_EXTENDED_SECURITY;

        synchronized (BUF) {
            System.arraycopy(sbuf, 0, BUF, 0, 4 + HEADER_LENGTH);
            final int size = Encdec.dec_uint16be(BUF, 2) & 0xFFFF;
            if (size < HEADER_LENGTH + 1 || 4 + size > rcv_buf_size) {
                throw new IOException("Invalid payload size: " + size);
            }
            final int errorCode = Encdec.dec_uint32le(BUF, 9) & 0xFFFFFFFF;
            if (resp.command == ServerMessageBlock.SMB_COM_READ_ANDX && (errorCode == 0 || errorCode == 0x80000005)) { // overflow indicator normal for pipe
                final SmbComReadAndXResponse r = (SmbComReadAndXResponse) resp;
                int off = HEADER_LENGTH;
                /* WordCount thru dataOffset always 27 */
                readn(in, BUF, 4 + off, 27);
                off += 27;
                resp.decode(BUF, 4);
                /* EMC can send pad w/o data */
                final int pad = r.dataOffset - off;
                if (r.byteCount > 0 && pad > 0 && pad < 4) {
                    readn(in, BUF, 4 + off, pad);
                }

                if (r.dataLength > 0) {
                    readn(in, r.b, r.off, r.dataLength); /* read direct */
                }
            } else {
                readn(in, BUF, 4 + 32, size - 32);
                resp.decode(BUF, 4);
                if (resp instanceof SmbComTransactionResponse) {
                    ((SmbComTransactionResponse) resp).nextElement();
                }
            }

            /* Verification fails (w/ W2K3 server at least) if status is not 0. This
             * suggests MS doesn't compute the signature (correctly) for error responses
             * (perhaps for DOS reasons).
             */
            if (digest != null && resp.errorCode == 0) {
                digest.verify(BUF, 4, resp);
            }

            if (LogStream.level >= 4) {
                log.println(response);
                if (LogStream.level >= 6) {
                    Hexdump.hexdump(log, BUF, 4, size);
                }
            }
        }
    }

    @Override
    protected void doSkip() throws IOException {
        final int size = Encdec.dec_uint16be(sbuf, 2) & 0xFFFF;
        if (size < 33 || 4 + size > rcv_buf_size) {
            /* log message? */
            in.skip(in.available());
        } else {
            in.skip(size - 32);
        }
    }

    void checkStatus(final ServerMessageBlock req, final ServerMessageBlock resp) throws SmbException {
        resp.errorCode = SmbException.getStatusByCode(resp.errorCode);
        switch (resp.errorCode) {
        case NtStatus.NT_STATUS_SUCCESS:
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
            throw new SmbAuthException(resp.errorCode);
        case NtStatus.NT_STATUS_PATH_NOT_COVERED:
            if (req.auth == null) {
                throw new SmbException(resp.errorCode, null);
            }

            final DfsReferral dr = getDfsReferrals(req.auth, req.path, 1);
            if (dr == null) {
                throw new SmbException(resp.errorCode, null);
            }

            SmbFile.dfs.insert(req.path, dr);
            throw dr;
        case 0x80000005: /* STATUS_BUFFER_OVERFLOW */
            break; /* normal for DCERPC named pipes */
        case NtStatus.NT_STATUS_MORE_PROCESSING_REQUIRED:
            break; /* normal for NTLMSSP */
        default:
            throw new SmbException(resp.errorCode, null);
        }
        if (resp.verifyFailed) {
            throw new SmbException("Signature verification failed.");
        }
    }

    void send(final ServerMessageBlock request, final ServerMessageBlock response) throws SmbException {

        connect(); /* must negotiate before we can test flags2, useUnicode, etc */

        request.flags2 |= flags2;
        request.useUnicode = useUnicode;
        request.response = response; /* needed by sign */
        if (request.digest == null) {
            request.digest = digest; /* for sign called in encode */
        }

        try {
            if (response == null) {
                doSend0(request);
                return;
            }
            if (request instanceof SmbComTransaction) {
                response.command = request.command;
                final SmbComTransaction req = (SmbComTransaction) request;
                final SmbComTransactionResponse resp = (SmbComTransactionResponse) response;

                req.maxBufferSize = snd_buf_size;
                resp.reset();

                try {
                    BufferCache.getBuffers(req, resp);

                    /*
                     * First request w/ interim response
                     */

                    req.nextElement();
                    if (req.hasMoreElements()) {
                        final SmbComBlankResponse interim = new SmbComBlankResponse();
                        super.sendrecv(req, interim, RESPONSE_TIMEOUT);
                        if (interim.errorCode != 0) {
                            checkStatus(req, interim);
                        }
                        req.nextElement();
                    } else {
                        makeKey(req);
                    }

                    synchronized (this) {
                        response.received = false;
                        resp.isReceived = false;
                        try {
                            response_map.put(req, resp);

                            /*
                             * Send multiple fragments
                             */

                            do {
                                doSend0(req);
                            } while (req.hasMoreElements() && req.nextElement() != null);

                            /*
                             * Receive multiple fragments
                             */

                            long timeout = RESPONSE_TIMEOUT;
                            resp.expiration = System.currentTimeMillis() + timeout;
                            while (resp.hasMoreElements()) {
                                wait(timeout);
                                timeout = resp.expiration - System.currentTimeMillis();
                                if (timeout <= 0) {
                                    throw new TransportException(this + " timedout waiting for response to " + req);
                                }
                            }
                            if (response.errorCode != 0) {
                                checkStatus(req, resp);
                            }
                        } catch (final InterruptedException ie) {
                            throw new TransportException(ie);
                        } finally {
                            response_map.remove(req);
                        }
                    }
                } finally {
                    BufferCache.releaseBuffer(req.txn_buf);
                    BufferCache.releaseBuffer(resp.txn_buf);
                }

            } else {
                response.command = request.command;
                super.sendrecv(request, response, RESPONSE_TIMEOUT);
            }
        } catch (final SmbException se) {
            throw se;
        } catch (final IOException ioe) {
            throw new SmbException(ioe.getMessage(), ioe);
        }

        checkStatus(request, response);
    }

    @Override
    public String toString() {
        return super.toString() + "[" + address + ":" + port + "]";
    }

    /* DFS */

    /* Split DFS path like \fs1.example.com\root5\link2\foo\bar.txt into at
     * most 3 components (not including the first index which is always empty):
     * result[0] = ""
     * result[1] = "fs1.example.com"
     * result[2] = "root5"
     * result[3] = "link2\foo\bar.txt"
     */
    void dfsPathSplit(final String path, final String[] result) {
        int ri = 0;
        final int rlast = result.length - 1;
        int i = 0, b = 0;
        final int len = path.length();

        do {
            if (ri == rlast) {
                result[rlast] = path.substring(b);
                return;
            }
            if (i == len || path.charAt(i) == '\\') {
                result[ri] = path.substring(b, i);
                ri++;
                b = i + 1;
            }
        } while (i++ < len);

        while (ri < result.length) {
            result[ri] = "";
            ri++;
        }
    }

    DfsReferral getDfsReferrals(final NtlmPasswordAuthentication auth, final String path, int rn) throws SmbException {
        final SmbTree ipc = getSmbSession(auth).getSmbTree("IPC$", null);
        final Trans2GetDfsReferralResponse resp = new Trans2GetDfsReferralResponse();
        ipc.send(new Trans2GetDfsReferral(path), resp);

        if (resp.numReferrals == 0) {
            return null;
        }
        if (rn == 0 || resp.numReferrals < rn) {
            rn = resp.numReferrals;
        }

        DfsReferral dr = new DfsReferral();

        final String[] arr = new String[4];
        final long expiration = System.currentTimeMillis() + Dfs.TTL * 1000;

        int di = 0;
        for (;;) {
            /* NTLM HTTP Authentication must be re-negotiated
             * with challenge from 'server' to access DFS vol. */
            dr.resolveHashes = auth.hashesExternal;
            dr.ttl = resp.referrals[di].ttl;
            dr.expiration = expiration;
            if (path.equals("")) {
                dr.server = resp.referrals[di].path.substring(1).toLowerCase();
            } else {
                dfsPathSplit(resp.referrals[di].node, arr);
                dr.server = arr[1];
                dr.share = arr[2];
                dr.path = arr[3];
            }
            dr.pathConsumed = resp.pathConsumed;

            di++;
            if (di == rn) {
                break;
            }

            dr.append(new DfsReferral());
            dr = dr.next;
        }

        return dr.next;
    }

    DfsReferral[] __getDfsReferrals(final NtlmPasswordAuthentication auth, final String path, int rn) throws SmbException {
        final SmbTree ipc = getSmbSession(auth).getSmbTree("IPC$", null);
        final Trans2GetDfsReferralResponse resp = new Trans2GetDfsReferralResponse();
        ipc.send(new Trans2GetDfsReferral(path), resp);

        if (rn == 0 || resp.numReferrals < rn) {
            rn = resp.numReferrals;
        }

        final DfsReferral[] drs = new DfsReferral[rn];
        final String[] arr = new String[4];
        final long expiration = System.currentTimeMillis() + Dfs.TTL * 1000;

        for (int di = 0; di < drs.length; di++) {
            final DfsReferral dr = new DfsReferral();
            /* NTLM HTTP Authentication must be re-negotiated
             * with challenge from 'server' to access DFS vol. */
            dr.resolveHashes = auth.hashesExternal;
            dr.ttl = resp.referrals[di].ttl;
            dr.expiration = expiration;
            if (path.equals("")) {
                dr.server = resp.referrals[di].path.substring(1).toLowerCase();
            } else {
                dfsPathSplit(resp.referrals[di].node, arr);
                dr.server = arr[1];
                dr.share = arr[2];
                dr.path = arr[3];
            }
            dr.pathConsumed = resp.pathConsumed;
            drs[di] = dr;
        }

        return drs;
    }

    //    FileEntry[] getDfsRoots(String domainName, NtlmPasswordAuthentication auth) throws IOException {
    //        MsrpcDfsRootEnum rpc;
    //        DcerpcHandle handle = null;
    //
    //        /* Procedure:
    //         * Lookup a DC in the target domain
    //         * Ask the DC for a referral for the domain (e.g. "\example.com")
    //         * Do NetrDfsEnumEx on the server returned in the referral to
    //         * get roots in target domain
    //         */
    //
    //        UniAddress dc = UniAddress.getByName(domainName);
    //        SmbTransport trans = SmbTransport.getSmbTransport(dc, 0);
    //        DfsReferral[] dr = trans.getDfsReferrals(auth, "\\" + domainName, 1);
    //
    //        handle = DcerpcHandle.getHandle("ncacn_np:" +
    //                    UniAddress.getByName(dr[0].server).getHostAddress() +
    //                    "[\\PIPE\\netdfs]", auth);
    //        try {
    //            rpc = new MsrpcDfsRootEnum(domainName);
    //            handle.sendrecv(rpc);
    //            if (rpc.retval != 0)
    //                throw new SmbSystemException(rpc.retval, true);
    //            return rpc.getEntries();
    //        } finally {
    //            try {
    //                handle.close();
    //            } catch(IOException ioe) {
    //                if (log.level >= 4)
    //                    ioe.printStackTrace(log);
    //            }
    //        }
    //    }
}
