/* jcifs msrpc client library in Java
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

package jcifs.dcerpc.msrpc;

import java.io.IOException;

import jcifs.internal.dtyp.ACE;
import jcifs.internal.dtyp.SecurityDescriptor;

/**
 * MSRPC implementation for retrieving share information.
 * This class provides functionality to get detailed information about
 * a specific share using the Server Service RPC interface.
 */
public class MsrpcShareGetInfo extends srvsvc.ShareGetInfo {

    /**
     * Creates a new request to get share information.
     *
     * @param server the server name
     * @param sharename the name of the share to query
     */
    public MsrpcShareGetInfo(final String server, final String sharename) {
        super(server, sharename, 502, new srvsvc.ShareInfo502());
        this.ptype = 0;
        this.flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
    }

    /**
     * Returns the security descriptor of the share as an array of ACEs.
     *
     * @return an array of ACE objects representing the share's security descriptor
     * @throws IOException if there is an error retrieving the security information
     */
    public ACE[] getSecurity() throws IOException {
        final srvsvc.ShareInfo502 info502 = (srvsvc.ShareInfo502) this.info;
        if (info502.security_descriptor != null) {
            SecurityDescriptor sd;
            sd = new SecurityDescriptor(info502.security_descriptor, 0, info502.sd_size);
            return sd.getAces();
        }
        return null;
    }
}
