/* org.codelibs.jcifs.smb msrpc client library in Java
 * Copyright (C) 2006  "Michael B. Allen" <jcifs at samba dot org>
 *                     "Eric Glass" <jcifs at samba dot org>
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

package org.codelibs.jcifs.smb.dcerpc;

import java.io.IOException;
import java.net.MalformedURLException;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.SmbNamedPipe;
import org.codelibs.jcifs.smb.SmbPipeHandleInternal;
import org.codelibs.jcifs.smb.SmbPipeResource;
import org.codelibs.jcifs.smb.util.Encdec;

/**
 * DCE/RPC handle implementation for named pipe communications.
 * This class provides DCE/RPC communication over SMB named pipes.
 */
public class DcerpcPipeHandle extends DcerpcHandle {

    /* This 0x20000 bit is going to get chopped! */
    final static int pipeFlags = 0x2019F << 16 | SmbPipeResource.PIPE_TYPE_RDWR | SmbPipeResource.PIPE_TYPE_DCE_TRANSACT;

    private final SmbNamedPipe pipe;
    private final SmbPipeHandleInternal handle;

    /**
     * Creates a DCERPC pipe handle for named pipe communication
     * @param url the DCERPC URL specifying the endpoint
     * @param tc the CIFS context for connection configuration
     * @param unshared whether to use an exclusive connection
     * @throws DcerpcException if DCERPC initialization fails
     * @throws MalformedURLException if the URL is malformed
     */
    public DcerpcPipeHandle(final String url, final CIFSContext tc, final boolean unshared) throws DcerpcException, MalformedURLException {
        super(tc, DcerpcHandle.parseBinding(url));
        this.pipe = new SmbNamedPipe(makePipeUrl(), pipeFlags, unshared, tc);
        this.handle = this.pipe.openPipe().unwrap(SmbPipeHandleInternal.class);
    }

    private String makePipeUrl() {
        final DcerpcBinding binding = getBinding();
        StringBuilder url =
                new StringBuilder("smb://").append(binding.getServer()).append("/IPC$/").append(binding.getEndpoint().substring(6));

        String params = "";
        final String server = (String) binding.getOption("server");
        if (server != null) {
            params += "&server=" + server;
        }
        final String address = (String) binding.getOption("address");
        if (address != null) {
            params += "&address=" + address;
        }
        if (params.length() > 0) {
            url.append("?").append(params.substring(1));
        }

        return url.toString();
    }

    @Override
    public CIFSContext getTransportContext() {
        return this.pipe.getContext();
    }

    @Override
    public String getServer() {
        return this.pipe.getLocator().getServer();
    }

    @Override
    public String getServerWithDfs() {
        return this.pipe.getLocator().getServerWithDfs();
    }

    @Override
    public byte[] getSessionKey() throws CIFSException {
        return this.handle.getSessionKey();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.dcerpc.DcerpcHandle#doSendReceiveFragment(byte[], int, int, byte[])
     */
    @Override
    protected int doSendReceiveFragment(final byte[] buf, final int off, final int length, final byte[] inB) throws IOException {
        if (this.handle.isStale()) {
            throw new IOException("DCERPC pipe is no longer open");
        }

        int have = this.handle.sendrecv(buf, off, length, inB, getMaxRecv());

        final int fraglen = Encdec.dec_uint16le(inB, 8);
        if (fraglen > getMaxRecv()) {
            throw new IOException("Unexpected fragment length: " + fraglen);
        }

        while (have < fraglen) {
            final int r = this.handle.recv(inB, have, fraglen - have);
            if (r == 0) {
                throw new IOException("Unexpected EOF");
            }
            have += r;
        }

        return have;
    }

    @Override
    protected void doSendFragment(final byte[] buf, final int off, final int length) throws IOException {
        if (this.handle.isStale()) {
            throw new IOException("DCERPC pipe is no longer open");
        }
        this.handle.send(buf, off, length);
    }

    @Override
    protected int doReceiveFragment(final byte[] buf) throws IOException {
        if (buf.length < getMaxRecv()) {
            throw new IllegalArgumentException("buffer too small");
        }

        int off = this.handle.recv(buf, 0, buf.length);
        if (buf[0] != 5 || buf[1] != 0) {
            throw new IOException("Unexpected DCERPC PDU header");
        }

        final int length = Encdec.dec_uint16le(buf, 8);
        if (length > getMaxRecv()) {
            throw new IOException("Unexpected fragment length: " + length);
        }

        while (off < length) {
            final int r = this.handle.recv(buf, off, length - off);
            if (r == 0) {
                throw new IOException("Unexpected EOF");
            }
            off += r;
        }
        return off;
    }

    @Override
    public void close() throws IOException {
        super.close();
        try {
            this.handle.close();
        } finally {
            this.pipe.close();
        }
    }
}
