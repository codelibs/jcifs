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

package org.codelibs.jcifs.smb1.dcerpc;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.UnknownHostException;

import org.codelibs.jcifs.smb1.NtlmPasswordAuthentication;
import org.codelibs.jcifs.smb1.SmbFileInputStream;
import org.codelibs.jcifs.smb1.SmbFileOutputStream;
import org.codelibs.jcifs.smb1.SmbNamedPipe;
import org.codelibs.jcifs.smb1.util.Encdec;

/**
 * DCERPC handle implementation using SMB named pipes for transport
 */
public class DcerpcPipeHandle extends DcerpcHandle {

    SmbNamedPipe pipe;
    SmbFileInputStream in = null;
    SmbFileOutputStream out = null;
    boolean isStart = true;

    /**
     * Creates a DCERPC pipe handle with the specified URL and authentication
     * @param url the DCERPC URL specifying the endpoint
     * @param auth the NTLM authentication credentials
     * @throws UnknownHostException if the host cannot be resolved
     * @throws MalformedURLException if the URL is malformed
     * @throws DcerpcException if DCERPC initialization fails
     */
    public DcerpcPipeHandle(String url, final NtlmPasswordAuthentication auth)
            throws UnknownHostException, MalformedURLException, DcerpcException {
        binding = DcerpcHandle.parseBinding(url);
        url = "smb1://" + binding.server + "/IPC$/" + binding.endpoint.substring(6);

        String params = "", server, address;
        server = (String) binding.getOption("server");
        if (server != null) {
            params += "&server=" + server;
        }
        address = (String) binding.getOption("address");
        if (server != null) {
            params += "&address=" + address;
        }
        if (params.length() > 0) {
            url += "?" + params.substring(1);
        }

        pipe = new SmbNamedPipe(url,
                /* This 0x20000 bit is going to get chopped! */
                0x2019F << 16 | SmbNamedPipe.PIPE_TYPE_RDWR | SmbNamedPipe.PIPE_TYPE_DCE_TRANSACT, auth);
    }

    @Override
    protected void doSendFragment(final byte[] buf, final int off, final int length, final boolean isDirect) throws IOException {
        if (out != null && !out.isOpen()) {
            throw new IOException("DCERPC pipe is no longer open");
        }

        if (in == null) {
            in = (SmbFileInputStream) pipe.getNamedPipeInputStream();
        }
        if (out == null) {
            out = (SmbFileOutputStream) pipe.getNamedPipeOutputStream();
        }
        if (isDirect) {
            out.writeDirect(buf, off, length, 1);
            return;
        }
        out.write(buf, off, length);
    }

    @Override
    protected void doReceiveFragment(final byte[] buf, final boolean isDirect) throws IOException {
        int off, flags, length;

        if (buf.length < max_recv) {
            throw new IllegalArgumentException("buffer too small");
        }

        if (isStart && !isDirect) { // start of new frag, do trans
            off = in.read(buf, 0, 1024);
        } else {
            off = in.readDirect(buf, 0, buf.length);
        }

        if (buf[0] != 5 && buf[1] != 0) {
            throw new IOException("Unexpected DCERPC PDU header");
        }

        flags = buf[3] & 0xFF;
        // next read is start of new frag
        isStart = (flags & DCERPC_LAST_FRAG) == DCERPC_LAST_FRAG;

        length = Encdec.dec_uint16le(buf, 8);
        if (length > max_recv) {
            throw new IOException("Unexpected fragment length: " + length);
        }

        while (off < length) {
            off += in.readDirect(buf, off, length - off);
        }
    }

    @Override
    public void close() throws IOException {
        state = 0;
        if (out != null) {
            out.close();
        }
    }
}
