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

package org.codelibs.jcifs.smb.internal.smb1.trans.nt;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.codelibs.jcifs.smb.util.Hexdump;

/**
 * SMB1 NT Transaction subcommand for querying security descriptors.
 *
 * This transaction allows retrieval of Windows security descriptors
 * which contain access control information for files and directories.
 */
public class NtTransQuerySecurityDesc extends SmbComNtTransaction {

    int fid;
    int securityInformation;

    /**
     * Constructs an NT transaction to query security descriptor information.
     * @param config the configuration context
     * @param fid the file identifier to query
     * @param securityInformation bitmask specifying which security information to retrieve
     */
    public NtTransQuerySecurityDesc(final Configuration config, final int fid, final int securityInformation) {
        super(config, NT_TRANSACT_QUERY_SECURITY_DESC);
        this.fid = fid;
        this.securityInformation = securityInformation;
        this.setupCount = 0;
        this.totalDataCount = 0;
        this.maxParameterCount = 4;
        this.maxDataCount = 65536;
        this.maxSetupCount = (byte) 0x00;
    }

    @Override
    public int getPadding() {
        return 4;
    }

    @Override
    protected int writeSetupWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    protected int writeParametersWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        SMBUtil.writeInt2(this.fid, dst, dstIndex);
        dstIndex += 2;
        dst[dstIndex] = (byte) 0x00; // Reserved
        dstIndex++;
        dst[dstIndex++] = (byte) 0x00; // Reserved
        SMBUtil.writeInt4(this.securityInformation, dst, dstIndex);
        dstIndex += 4;
        return dstIndex - start;
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
        return 0;
    }

    @Override
    protected int readDataWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        return 0;
    }

    @Override
    public String toString() {
        return ("NtTransQuerySecurityDesc[" + super.toString() + ",fid=0x" + Hexdump.toHexString(this.fid, 4) + ",securityInformation=0x"
                + Hexdump.toHexString(this.securityInformation, 8) + "]");
    }
}
