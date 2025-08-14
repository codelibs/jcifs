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

package jcifs.smb1.smb1;

import java.io.IOException;

class NtTransQuerySecurityDescResponse extends SmbComNtTransactionResponse {

    SecurityDescriptor securityDescriptor;

    NtTransQuerySecurityDescResponse() {
    }

    @Override
    int writeSetupWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    int writeParametersWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    int writeDataWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    int readSetupWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        return 0;
    }

    @Override
    int readParametersWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        length = readInt4(buffer, bufferIndex);
        return 4;
    }

    @Override
    int readDataWireFormat(final byte[] buffer, int bufferIndex, final int len) {
        final int start = bufferIndex;

        if (errorCode != 0) {
            return 4;
        }

        try {
            securityDescriptor = new SecurityDescriptor();
            bufferIndex += securityDescriptor.decode(buffer, bufferIndex, len);
        } catch (final IOException ioe) {
            throw new RuntimeException(ioe.getMessage());
        }

        return bufferIndex - start;
    }

    @Override
    public String toString() {
        return ("NtTransQuerySecurityResponse[" + super.toString() + "]");
    }
}
