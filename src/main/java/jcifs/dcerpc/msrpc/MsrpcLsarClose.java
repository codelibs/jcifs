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

import jcifs.dcerpc.rpc.policy_handle;
import jcifs.dcerpc.msrpc.lsarpc.LsarClose;

/**
 * Microsoft RPC LSA close handle request.
 * This class implements the LSARPC close handle operation.
 */
public class MsrpcLsarClose extends LsarClose {

    /**
     * Creates a new request to close an LSA policy handle.
     *
     * @param handle the policy handle to close
     */
    public MsrpcLsarClose(final policy_handle handle) {
        super(handle);
        this.ptype = 0;
        this.flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
    }

}
