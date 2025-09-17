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

package org.codelibs.jcifs.smb1.dcerpc.msrpc;

/**
 * MSRPC implementation for retrieving members of an alias.
 * This class provides functionality to get the list of security identifiers (SIDs)
 * that are members of a specific alias using the SAMR RPC interface.
 */
public class MsrpcGetMembersInAlias extends samr.SamrGetMembersInAlias {

    /**
     * Creates a new request to get members of an alias.
     *
     * @param aliasHandle the handle to the alias
     * @param sids the SID array to store the member SIDs
     */
    public MsrpcGetMembersInAlias(final SamrAliasHandle aliasHandle, final lsarpc.LsarSidArray sids) {
        super(aliasHandle, sids);
        this.sids = sids;
        ptype = 0;
        flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
    }
}
