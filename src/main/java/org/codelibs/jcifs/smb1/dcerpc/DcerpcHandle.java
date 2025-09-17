/* org.codelibs.jcifs.smb msrpc client library in Java
 * Copyright (C) 2006  "Michael B. Allen" <jcifs at samba dot org>
 *                   "Eric Glass" <jcifs at samba dot org>
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

package org.codelibs.jcifs.smb1.dcerpc;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.security.Principal;

import org.codelibs.jcifs.smb1.NtlmPasswordAuthentication;
import org.codelibs.jcifs.smb1.dcerpc.ndr.NdrBuffer;

/**
 * Abstract base class for DCERPC handles providing core RPC functionality.
 * This class manages DCE/RPC protocol bindings and communications over SMB transport.
 */
public abstract class DcerpcHandle implements DcerpcConstants {

    /**
     * Default constructor for DcerpcHandle.
     * Initializes the DCE/RPC handle for protocol operations.
     */
    protected DcerpcHandle() {
        // Default constructor
    }

    /* Bindings are in the form:
     * proto:\\server[key1=val1,key2=val2]
     * or
     * proto:server[key1=val1,key2=val2]
     * or
     * proto:[key1=val1,key2=val2]
     *
     * If a key is absent it is assumed to be 'endpoint'. Thus the
     * following are equivalent:
     * proto:\\ts0.win.net[endpoint=\pipe\srvsvc]
     * proto:ts0.win.net[\pipe\srvsvc]
     *
     * If the server is absent it is set to "127.0.0.1"
     */
    /**
     * Parses a DCERPC binding string into a DcerpcBinding object
     * @param str the binding string to parse
     * @return the parsed DcerpcBinding object
     * @throws DcerpcException if the binding string is malformed
     */
    protected static DcerpcBinding parseBinding(final String str) throws DcerpcException {
        int state, mark, si;
        final char[] arr = str.toCharArray();
        String proto = null, key = null;
        DcerpcBinding binding = null;

        state = mark = si = 0;
        do {
            final char ch = arr[si];

            switch (state) {
            case 0:
                if (ch == ':') {
                    proto = str.substring(mark, si);
                    mark = si + 1;
                    state = 1;
                }
                break;
            case 1:
                if (ch == '\\') {
                    mark = si + 1;
                    break;
                }
                state = 2;
            case 2:
                if (ch == '[') {
                    String server = str.substring(mark, si).trim();
                    if (server.length() == 0) {
                        server = "127.0.0.1";
                    }
                    binding = new DcerpcBinding(proto, str.substring(mark, si));
                    mark = si + 1;
                    state = 5;
                }
                break;
            case 5:
                if (ch == '=') {
                    key = str.substring(mark, si).trim();
                    mark = si + 1;
                } else if (ch == ',' || ch == ']') {
                    final String val = str.substring(mark, si).trim();
                    if (key == null) {
                        key = "endpoint";
                    }
                    binding.setOption(key, val);
                    key = null;
                }
                break;
            default:
                si = arr.length;
            }

            si++;
        } while (si < arr.length);

        if (binding == null || binding.endpoint == null) {
            throw new DcerpcException("Invalid binding URL: " + str);
        }

        return binding;
    }

    /**
     * The DCERPC binding configuration for this handle
     */
    protected DcerpcBinding binding;
    /**
     * Maximum transmit buffer size for DCERPC messages
     */
    protected int max_xmit = 4280;
    /**
     * Maximum receive buffer size for DCERPC messages
     */
    protected int max_recv = max_xmit;
    /**
     * The current state of the DCERPC connection
     */
    protected int state = 0;
    /**
     * The security provider for authentication and message protection
     */
    protected DcerpcSecurityProvider securityProvider = null;
    private static int call_id = 1;

    /**
     * Gets a DCERPC handle for the specified URL and authentication
     * @param url the DCERPC URL to connect to
     * @param auth the NTLM authentication credentials
     * @return a DCERPC handle for the connection
     * @throws UnknownHostException if the host cannot be resolved
     * @throws MalformedURLException if the URL is malformed
     * @throws DcerpcException if DCERPC initialization fails
     */
    public static DcerpcHandle getHandle(final String url, final NtlmPasswordAuthentication auth)
            throws UnknownHostException, MalformedURLException, DcerpcException {
        if (url.startsWith("ncacn_np:")) {
            return new DcerpcPipeHandle(url, auth);
        }
        throw new DcerpcException("DCERPC transport not supported: " + url);
    }

    /**
     * Binds this handle to the remote DCERPC endpoint
     * @throws DcerpcException if the bind operation fails
     * @throws IOException if an I/O error occurs
     */
    public void bind() throws DcerpcException, IOException {
        synchronized (this) {
            try {
                state = 1;
                final DcerpcMessage bind = new DcerpcBind(binding, this);
                sendrecv(bind);
            } catch (final IOException ioe) {
                state = 0;
                throw ioe;
            }
        }
    }

    /**
     * Sends a DCERPC message and receives the response
     * @param msg the message to send
     * @throws DcerpcException if the RPC operation fails
     * @throws IOException if an I/O error occurs
     */
    public void sendrecv(final DcerpcMessage msg) throws DcerpcException, IOException {
        byte[] stub, frag;
        NdrBuffer buf, fbuf;
        final boolean isLast;
        boolean isDirect;
        DcerpcException de;

        if (state == 0) {
            bind();
        }

        isDirect = true;

        stub = org.codelibs.jcifs.smb1.BufferCache.getBuffer();
        try {
            int off, tot, n;

            buf = new NdrBuffer(stub, 0);

            msg.flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
            msg.call_id = call_id++;

            msg.encode(buf);

            if (securityProvider != null) {
                buf.setIndex(0);
                securityProvider.wrap(buf);
            }

            tot = buf.getLength() - 24;
            off = 0;

            while (off < tot) {
                n = tot - off;

                if (24 + n > max_xmit) {
                    msg.flags &= ~DCERPC_LAST_FRAG;
                    n = max_xmit - 24;
                } else {
                    msg.flags |= DCERPC_LAST_FRAG;
                    isDirect = false;
                    msg.alloc_hint = n;
                }

                msg.length = 24 + n;

                if (off > 0) {
                    msg.flags &= ~DCERPC_FIRST_FRAG;
                }

                if ((msg.flags & (DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG)) != (DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG)) {
                    buf.start = off;
                    buf.reset();
                    msg.encode_header(buf);
                    buf.enc_ndr_long(msg.alloc_hint);
                    buf.enc_ndr_short(0); /* context id */
                    buf.enc_ndr_short(msg.getOpnum());
                }

                doSendFragment(stub, off, msg.length, isDirect);
                off += n;
            }

            doReceiveFragment(stub, isDirect);
            buf.reset();
            buf.setIndex(8);
            buf.setLength(buf.dec_ndr_short());

            if (securityProvider != null) {
                securityProvider.unwrap(buf);
            }

            buf.setIndex(0);

            msg.decode_header(buf);

            off = 24;
            if (msg.ptype == 2 && !msg.isFlagSet(DCERPC_LAST_FRAG)) {
                off = msg.length;
            }

            frag = null;
            fbuf = null;
            while (!msg.isFlagSet(DCERPC_LAST_FRAG)) {
                int stub_frag_len;

                if (frag == null) {
                    frag = new byte[max_recv];
                    fbuf = new NdrBuffer(frag, 0);
                }

                doReceiveFragment(frag, isDirect);
                fbuf.reset();
                fbuf.setIndex(8);
                fbuf.setLength(fbuf.dec_ndr_short());

                if (securityProvider != null) {
                    securityProvider.unwrap(fbuf);
                }

                fbuf.reset();
                msg.decode_header(fbuf);
                stub_frag_len = msg.length - 24;

                if (off + stub_frag_len > stub.length) {
                    // shouldn't happen if alloc_hint is correct or greater
                    final byte[] tmp = new byte[off + stub_frag_len];
                    System.arraycopy(stub, 0, tmp, 0, off);
                    stub = tmp;
                }

                System.arraycopy(frag, 24, stub, off, stub_frag_len);
                off += stub_frag_len;
            }

            buf = new NdrBuffer(stub, 0);
            msg.decode(buf);
        } finally {
            org.codelibs.jcifs.smb1.BufferCache.releaseBuffer(stub);
        }

        de = msg.getResult();
        if (de != null) {
            throw de;
        }
    }

    /**
     * Sets the security provider for this handle
     * @param securityProvider the security provider to use
     */
    public void setDcerpcSecurityProvider(final DcerpcSecurityProvider securityProvider) {
        this.securityProvider = securityProvider;
    }

    /**
     * Gets the server hostname or address
     * @return the server name
     */
    public String getServer() {
        if (this instanceof DcerpcPipeHandle) {
            return ((DcerpcPipeHandle) this).pipe.getServer();
        }
        return null;
    }

    /**
     * Gets the principal associated with this handle
     * @return the principal or null if not authenticated
     */
    public Principal getPrincipal() {
        if (this instanceof DcerpcPipeHandle) {
            return ((DcerpcPipeHandle) this).pipe.getPrincipal();
        }
        return null;
    }

    @Override
    public String toString() {
        return binding.toString();
    }

    /**
     * Sends a DCERPC fragment to the remote endpoint
     * @param buf the buffer containing the fragment
     * @param off the offset into the buffer
     * @param length the length of data to send
     * @param isDirect whether to use direct transmission
     * @throws IOException if an I/O error occurs
     */
    protected abstract void doSendFragment(byte[] buf, int off, int length, boolean isDirect) throws IOException;

    /**
     * Receives a DCERPC fragment from the remote endpoint
     * @param buf the buffer to receive the fragment
     * @param isDirect whether to use direct reception
     * @throws IOException if an I/O error occurs
     */
    protected abstract void doReceiveFragment(byte[] buf, boolean isDirect) throws IOException;

    /**
     * Closes this DCERPC handle and releases resources
     * @throws IOException if an I/O error occurs during close
     */
    public abstract void close() throws IOException;
}
