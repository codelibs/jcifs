/* jcifs smb client library in Java
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

package jcifs.internal.smb1.trans2;

import jcifs.Configuration;
import jcifs.internal.dfs.DfsReferralRequestBuffer;
import jcifs.internal.smb1.trans.SmbComTransaction;

/**
 *
 */
public class Trans2GetDfsReferral extends SmbComTransaction {

    private final int maxReferralLevel;

    private final DfsReferralRequestBuffer request;

    /**
     *
     * @param config
     * @param filename
     */
    public Trans2GetDfsReferral(final Configuration config, final String filename) {
        this(config, filename, 3);
    }

    /**
     *
     * @param config
     * @param filename
     * @param maxReferralLevel
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
     * @see jcifs.internal.smb1.ServerMessageBlock#isForceUnicode()
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
