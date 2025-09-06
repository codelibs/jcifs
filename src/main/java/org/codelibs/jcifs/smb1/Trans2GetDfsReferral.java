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

package org.codelibs.jcifs.smb1;

class Trans2GetDfsReferral extends SmbComTransaction {

    private final int maxReferralLevel;

    Trans2GetDfsReferral(final String filename) {
        this(filename, 3);
    }

    Trans2GetDfsReferral(final String filename, final int maxReferralLevel) {
        this.maxReferralLevel = maxReferralLevel;
        path = filename;
        command = SMB_COM_TRANSACTION2;
        subCommand = TRANS2_GET_DFS_REFERRAL;
        totalDataCount = 0;
        maxParameterCount = 0;
        maxDataCount = 4096;
        maxSetupCount = (byte) 0x00;
    }

    @Override
    int writeSetupWireFormat(final byte[] dst, int dstIndex) {
        dst[dstIndex] = subCommand;
        dstIndex++;
        dst[dstIndex++] = (byte) 0x00;
        return 2;
    }

    @Override
    int writeParametersWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        writeInt2(maxReferralLevel, dst, dstIndex);
        dstIndex += 2;
        dstIndex += writeString(path, dst, dstIndex);

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
        return ("Trans2GetDfsReferral[" + super.toString() + ",maxReferralLevel=0x" + maxReferralLevel + ",filename=" + path + "]");
    }
}
