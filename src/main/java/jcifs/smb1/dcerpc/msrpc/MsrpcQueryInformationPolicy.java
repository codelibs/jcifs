/* jcifs msrpc client library in Java
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

package jcifs.smb1.dcerpc.msrpc;

import jcifs.smb1.dcerpc.ndr.NdrObject;

/**
 * MSRPC implementation for querying LSA policy information.
 * This class provides functionality to retrieve information about
 * LSA policy settings using the LSA RPC interface.
 */
public class MsrpcQueryInformationPolicy extends lsarpc.LsarQueryInformationPolicy {

    /**
     * Creates a new request to query LSA policy information.
     *
     * @param policyHandle the LSA policy handle
     * @param level the information level to query
     * @param info the object to store the query results
     */
    public MsrpcQueryInformationPolicy(final LsaPolicyHandle policyHandle, final short level, final NdrObject info) {
        super(policyHandle, level, info);
        ptype = 0;
        flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
    }
}
