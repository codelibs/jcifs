/*
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
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

package org.codelibs.jcifs.smb.internal.smb1.trans2;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.dfs.DfsReferralRequestBuffer;
import org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransaction;

/**
 * Trans2 GetDfsReferral request message for DFS referral queries.
 * This class implements the TRANS2_GET_DFS_REFERRAL transaction to request
 * DFS referral information for distributed file system path resolution.
 */
public class Trans2GetDfsReferral extends SmbComTransaction {

    private final int maxReferralLevel;

    private final DfsReferralRequestBuffer request;

    /**
     * Constructs a Trans2GetDfsReferral request with default referral level.
     *
     * @param config the configuration to use
     * @param filename the DFS path to get referrals for
     */
    public Trans2GetDfsReferral(final Configuration config, final String filename) {
        this(config, filename, 3);
    }

    /**
     * Constructs a Trans2GetDfsReferral request with specified referral level.
     *
     * @param config the configuration to use
     * @param filename the DFS path to get referrals for
     * @param maxReferralLevel the maximum referral level to request
     */
    public Trans2GetDfsReferral(final Configuration config, final String filename, final int maxReferralLevel) {
        super(config, SMB_COM_TRANSACTION2, TRANS2_GET_DFS_REFERRAL);
        this.maxReferralLevel = maxReferralLevel;
        this.request = new DfsReferralRequestBuffer(filename, maxReferralLevel);
        this.totalDataCount = 0;
        this.maxParameterCount = 0;
        this.maxDataCount = 4096;
        this.maxSetupCount = (byte) 0x00;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock#isForceUnicode()
     */
    @Override
    public boolean isForceUnicode() {
        return true;
    }

    @Override
    protected int writeSetupWireFormat(final byte[] dst, int dstIndex) {
        dst[dstIndex] = this.getSubCommand();
        dstIndex++;
        dst[dstIndex++] = (byte) 0x00;
        return 2;
    }

    @Override
    protected int writeParametersWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        dstIndex += this.request.encode(dst, dstIndex);
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
        return ("Trans2GetDfsReferral[" + super.toString() + ",maxReferralLevel=0x" + this.maxReferralLevel + ",filename=" + this.path
                + "]");
    }
}
