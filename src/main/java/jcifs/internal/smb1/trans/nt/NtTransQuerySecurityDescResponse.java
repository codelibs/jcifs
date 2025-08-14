/* jcifs smb client library in Java
 * Copyright (C) 2005  "Michael B. Allen" <jcifs at samba dot org>
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

package jcifs.internal.smb1.trans.nt;

import java.io.IOException;

import jcifs.Configuration;
import jcifs.RuntimeCIFSException;
import jcifs.internal.dtyp.SecurityDescriptor;
import jcifs.internal.util.SMBUtil;

/**
 * Response for SMB1 NT Transaction security descriptor query.
 *
 * This response contains the Windows security descriptor retrieved
 * from the server, including access control information.
 */
public class NtTransQuerySecurityDescResponse extends SmbComNtTransactionResponse {

    private SecurityDescriptor securityDescriptor;

    /**
     *
     * @param config
     */
    public NtTransQuerySecurityDescResponse(final Configuration config) {
        super(config);
    }

    /**
     * @return the securityDescriptor
     */
    public final SecurityDescriptor getSecurityDescriptor() {
        return this.securityDescriptor;
    }

    @Override
    protected int writeSetupWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    protected int writeParametersWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    protected int writeDataWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    protected int readSetupWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        return 0;
    }

    @Override
    protected int readParametersWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        this.length = SMBUtil.readInt4(buffer, bufferIndex);
        return 4;
    }

    @Override
    protected int readDataWireFormat(final byte[] buffer, int bufferIndex, final int len) {
        final int start = bufferIndex;

        if (this.getErrorCode() != 0) {
            return 4;
        }

        try {
            this.securityDescriptor = new SecurityDescriptor();
            bufferIndex += this.securityDescriptor.decode(buffer, bufferIndex, len);
        } catch (final IOException ioe) {
            throw new RuntimeCIFSException(ioe.getMessage());
        }

        return bufferIndex - start;
    }

    @Override
    public String toString() {
        return ("NtTransQuerySecurityResponse[" + super.toString() + "]");
    }
}
