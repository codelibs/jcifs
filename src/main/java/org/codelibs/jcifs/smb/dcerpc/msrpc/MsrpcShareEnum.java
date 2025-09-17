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

package org.codelibs.jcifs.smb.dcerpc.msrpc;

import org.codelibs.jcifs.smb.impl.FileEntry;
import org.codelibs.jcifs.smb.internal.smb1.net.SmbShareInfo;

/**
 * MSRPC implementation for enumerating shares.
 * This class provides functionality to enumerate shared resources
 * on a server using the Server Service RPC interface.
 */
public class MsrpcShareEnum extends srvsvc.ShareEnumAll {

    class MsrpcShareInfo1 extends SmbShareInfo {

        MsrpcShareInfo1(final srvsvc.ShareInfo1 info1) {
            this.netName = info1.netname;
            this.type = info1.type;
            this.remark = info1.remark;
        }
    }

    /**
     * Creates a new request to enumerate shares on a server.
     *
     * @param server the server name to enumerate shares from
     */
    public MsrpcShareEnum(final String server) {
        super("\\\\" + server, 1, new srvsvc.ShareInfoCtr1(), -1, 0, 0);
        this.ptype = 0;
        this.flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
    }

    /**
     * Returns the share entries retrieved from the enumeration.
     *
     * @return an array of FileEntry objects representing the shares
     */
    public FileEntry[] getEntries() {
        /*
         * The ShareInfo1 class does not implement the FileEntry
         * interface (because it is generated from IDL). Therefore
         * we must create an array of objects that do.
         */
        final srvsvc.ShareInfoCtr1 ctr = (srvsvc.ShareInfoCtr1) this.info;
        final MsrpcShareInfo1[] entries = new MsrpcShareInfo1[ctr.count];
        for (int i = 0; i < ctr.count; i++) {
            entries[i] = new MsrpcShareInfo1(ctr.array[i]);
        }
        return entries;
    }
}
