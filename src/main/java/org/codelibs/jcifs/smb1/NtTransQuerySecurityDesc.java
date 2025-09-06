/*
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

package org.codelibs.jcifs.smb1;

import org.codelibs.jcifs.smb1.util.Hexdump;

class NtTransQuerySecurityDesc extends SmbComNtTransaction {

    int fid;
    int securityInformation;

    NtTransQuerySecurityDesc(final int fid, final int securityInformation) {
        this.fid = fid;
        this.securityInformation = securityInformation;
        command = SMB_COM_NT_TRANSACT;
        function = NT_TRANSACT_QUERY_SECURITY_DESC;
        setupCount = 0;
        totalDataCount = 0;
        maxParameterCount = 4;
        maxDataCount = 32768;
        maxSetupCount = (byte) 0x00;
    }

    @Override
    int writeSetupWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    int writeParametersWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        writeInt2(fid, dst, dstIndex);
        dstIndex += 2;
        dst[dstIndex] = (byte) 0x00; // Reserved
        dstIndex++;
        dst[dstIndex++] = (byte) 0x00; // Reserved
        writeInt4(securityInformation, dst, dstIndex);
        dstIndex += 4;

        return dstIndex - start;
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
        return 0;
    }

    @Override
    int readDataWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        return 0;
    }

    @Override
    public String toString() {
        return ("NtTransQuerySecurityDesc[" + super.toString() + ",fid=0x" + Hexdump.toHexString(fid, 4) + ",securityInformation=0x"
                + Hexdump.toHexString(securityInformation, 8) + "]");
    }
}
