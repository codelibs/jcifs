/* org.codelibs.jcifs.smb msrpc client library in Java
 * Copyright (C) 2007  "Michael B. Allen" <jcifs at samba dot org>
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

package org.codelibs.jcifs.smb.dcerpc.msrpc;

import java.io.IOException;

import org.codelibs.jcifs.smb.SmbException;
import org.codelibs.jcifs.smb.dcerpc.DcerpcError;
import org.codelibs.jcifs.smb.dcerpc.DcerpcException;
import org.codelibs.jcifs.smb.dcerpc.DcerpcHandle;
import org.codelibs.jcifs.smb.dcerpc.rpc;

/**
 * Handle for Security Account Manager (SAM) policy operations.
 * This class represents an open handle to a SAM server and provides
 * high-level access to SAM database operations.
 */
public class SamrPolicyHandle extends rpc.policy_handle implements AutoCloseable {

    private final DcerpcHandle handle;
    private boolean opened;

    /**
     * Creates a new SAM policy handle.
     *
     * @param handle the DCE/RPC handle for communication
     * @param server the server name (null defaults to local server)
     * @param access the desired access rights
     * @throws IOException if an I/O error occurs during handle creation
     */
    public SamrPolicyHandle(final DcerpcHandle handle, String server, final int access) throws IOException {
        this.handle = handle;
        if (server == null) {
            server = "\\\\";
        }
        final MsrpcSamrConnect4 rpc = new MsrpcSamrConnect4(server, access, this);
        try {
            handle.sendrecv(rpc);
        } catch (final DcerpcException de) {
            if (de.getErrorCode() != DcerpcError.DCERPC_FAULT_OP_RNG_ERROR) {
                throw de;
            }
            final MsrpcSamrConnect2 rpc2 = new MsrpcSamrConnect2(server, access, this);
            handle.sendrecv(rpc2);
        }
        this.opened = true;
    }

    @Override
    public synchronized void close() throws IOException {
        if (this.opened) {
            this.opened = false;
            final samr.SamrCloseHandle rpc = new MsrpcSamrCloseHandle(this);
            this.handle.sendrecv(rpc);
            if (rpc.retval != 0) {
                throw new SmbException(rpc.retval, false);
            }
        }
    }
}
