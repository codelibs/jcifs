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

package org.codelibs.jcifs.smb1.dcerpc.msrpc;

import org.codelibs.jcifs.smb1.SID;

/**
 * MSRPC implementation for looking up security identifiers (SIDs).
 * This class provides functionality to resolve SIDs to their corresponding
 * account names using the LSA RPC interface.
 */
public class MsrpcLookupSids extends lsarpc.LsarLookupSids {

    SID[] sids;

    /**
     * Creates a new request to lookup SIDs.
     *
     * @param policyHandle the LSA policy handle
     * @param sids the array of SIDs to lookup
     */
    public MsrpcLookupSids(final LsaPolicyHandle policyHandle, final SID[] sids) {
        super(policyHandle, new LsarSidArrayX(sids), new lsarpc.LsarRefDomainList(), new lsarpc.LsarTransNameArray(), (short) 1,
                sids.length);
        this.sids = sids;
        ptype = 0;
        flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
    }
}
