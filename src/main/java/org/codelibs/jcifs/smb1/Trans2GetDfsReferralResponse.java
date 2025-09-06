/*
 * Copyright (C) 2003  "Michael B. Allen" <jcifs at samba dot org>
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

class Trans2GetDfsReferralResponse extends SmbComTransactionResponse {

    class Referral {
        private int version;
        private int size;
        private int serverType;
        private int flags;
        private int proximity;
        private int pathOffset;
        private int altPathOffset;
        private int nodeOffset;
        private String altPath;

        int ttl;
        String path = null;
        String node = null;

        int readWireFormat(final byte[] buffer, int bufferIndex, final int len) {
            final int start = bufferIndex;

            version = readInt2(buffer, bufferIndex);
            if (version != 3 && version != 1) {
                throw new RuntimeException("Version " + version + " referral not supported. Please report this to jcifs at samba dot org.");
            }
            bufferIndex += 2;
            size = readInt2(buffer, bufferIndex);
            bufferIndex += 2;
            serverType = readInt2(buffer, bufferIndex);
            bufferIndex += 2;
            flags = readInt2(buffer, bufferIndex);
            bufferIndex += 2;
            if (version == 3) {
                proximity = readInt2(buffer, bufferIndex);
                bufferIndex += 2;
                ttl = readInt2(buffer, bufferIndex);
                bufferIndex += 2;
                pathOffset = readInt2(buffer, bufferIndex);
                bufferIndex += 2;
                altPathOffset = readInt2(buffer, bufferIndex);
                bufferIndex += 2;
                nodeOffset = readInt2(buffer, bufferIndex);
                bufferIndex += 2;

                path = readString(buffer, start + pathOffset, len, (flags2 & FLAGS2_UNICODE) != 0);
                if (nodeOffset > 0) {
                    node = readString(buffer, start + nodeOffset, len, (flags2 & FLAGS2_UNICODE) != 0);
                }
            } else if (version == 1) {
                node = readString(buffer, bufferIndex, len, (flags2 & FLAGS2_UNICODE) != 0);
            }

            return size;
        }

        @Override
        public String toString() {
            return ("Referral[" + "version=" + version + ",size=" + size + ",serverType=" + serverType + ",flags=" + flags + ",proximity="
                    + proximity + ",ttl=" + ttl + ",pathOffset=" + pathOffset + ",altPathOffset=" + altPathOffset + ",nodeOffset="
                    + nodeOffset + ",path=" + path + ",altPath=" + altPath + ",node=" + node + "]");
        }
    }

    int pathConsumed;
    int numReferrals;
    int flags;
    Referral[] referrals;

    Trans2GetDfsReferralResponse() {
        subCommand = SmbComTransaction.TRANS2_GET_DFS_REFERRAL;
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
        return 0;
    }

    @Override
    int readDataWireFormat(final byte[] buffer, int bufferIndex, final int len) {
        final int start = bufferIndex;

        pathConsumed = readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        /* Samba 2.2.8a will reply with Unicode paths even though
         * ASCII is negotiated so we must use flags2 (probably
         * should anyway).
         */
        if ((flags2 & FLAGS2_UNICODE) != 0) {
            pathConsumed /= 2;
        }
        numReferrals = readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        flags = readInt2(buffer, bufferIndex);
        bufferIndex += 4;

        referrals = new Referral[numReferrals];
        for (int ri = 0; ri < numReferrals; ri++) {
            referrals[ri] = new Referral();
            bufferIndex += referrals[ri].readWireFormat(buffer, bufferIndex, len);
        }

        return bufferIndex - start;
    }

    @Override
    public String toString() {
        return ("Trans2GetDfsReferralResponse[" + super.toString() + ",pathConsumed=" + pathConsumed + ",numReferrals=" + numReferrals
                + ",flags=" + flags + "]");
    }
}
