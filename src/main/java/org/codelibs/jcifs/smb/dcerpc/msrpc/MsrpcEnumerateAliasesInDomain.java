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

/**
 * MSRPC implementation for enumerating aliases within a domain.
 * This class provides functionality to enumerate security aliases (local groups)
 * within a SAM domain using the SAMR RPC interface.
 */
public class MsrpcEnumerateAliasesInDomain extends samr.SamrEnumerateAliasesInDomain {

    /**
     * Creates a new request to enumerate aliases in a domain.
     *
     * @param domainHandle the handle to the SAM domain
     * @param acct_flags account flags to filter the enumeration
     * @param sam the SAM array to store the enumeration results
     */
    public MsrpcEnumerateAliasesInDomain(final SamrDomainHandle domainHandle, final int acct_flags, final samr.SamrSamArray sam) {
        super(domainHandle, 0, acct_flags, null, 0);
        this.sam = sam;
        this.ptype = 0;
        this.flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
    }
}
