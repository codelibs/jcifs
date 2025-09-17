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

import org.codelibs.jcifs.smb.dcerpc.DcerpcHandle;
import org.codelibs.jcifs.smb.dcerpc.rpc;
import org.codelibs.jcifs.smb.impl.SmbException;

/**
 * Handle for Security Account Manager (SAM) domain operations.
 * This class represents an open handle to a SAM domain and provides
 * operations for managing domain users, groups, and aliases.
 */
public class SamrDomainHandle extends rpc.policy_handle implements AutoCloseable {

    private final DcerpcHandle handle;
    private boolean opened;

    /**
     * Creates a new SAM domain handle.
     *
     * @param handle the DCE/RPC handle for communication
     * @param policyHandle the policy handle for this domain
     * @param access the desired access rights
     * @param sid the security identifier of the domain
     * @throws IOException if an I/O error occurs during handle creation
     */
    public SamrDomainHandle(final DcerpcHandle handle, final SamrPolicyHandle policyHandle, final int access, final rpc.sid_t sid)
            throws IOException {
        this.handle = handle;
        final MsrpcSamrOpenDomain rpc = new MsrpcSamrOpenDomain(policyHandle, access, sid, this);
        handle.sendrecv(rpc);
        if (rpc.retval != 0) {
            throw new SmbException(rpc.retval, false);
        }
        this.opened = true;
    }

    @Override
    public synchronized void close() throws IOException {
        if (this.opened) {
            this.opened = false;
            final MsrpcSamrCloseHandle rpc = new MsrpcSamrCloseHandle(this);
            this.handle.sendrecv(rpc);
            if (rpc.retval != 0) {
                throw new SmbException(rpc.retval, false);
            }
        }
    }
}
