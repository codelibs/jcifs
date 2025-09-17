/* org.codelibs.jcifs.smb smb client library in Java
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

package org.codelibs.jcifs.smb.internal.smb1.trans2;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.dfs.DfsReferralResponseBuffer;
import org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransaction;
import org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransactionResponse;

/**
 * Trans2 GetDfsReferral response message for DFS referral queries.
 * This class handles the response from a TRANS2_GET_DFS_REFERRAL request, which returns
 * DFS referral information for redirecting clients to distributed file system targets.
 */
public class Trans2GetDfsReferralResponse extends SmbComTransactionResponse {

    /**
     * Indicates that the referral contains a name list.
     */
    public static final int FLAGS_NAME_LIST_REFERRAL = 0x0002;
    /**
     * Indicates a target set boundary in the referral response.
     */
    public static final int FLAGS_TARGET_SET_BOUNDARY = 0x0004;
    /**
     * Indicates root targets in the DFS referral.
     */
    public static final int TYPE_ROOT_TARGETS = 0x0;
    /**
     * Indicates non-root targets in the DFS referral.
     */
    public static final int TYPE_NON_ROOT_TARGETS = 0x1;

    private final DfsReferralResponseBuffer dfsResponse = new DfsReferralResponseBuffer();

    /**
     * Constructs a Trans2GetDfsReferralResponse with the specified configuration.
     *
     * @param config the SMB configuration
     */
    public Trans2GetDfsReferralResponse(final Configuration config) {
        super(config);
        this.setSubCommand(SmbComTransaction.TRANS2_GET_DFS_REFERRAL);
    }

    /**
     * Gets the DFS referral response buffer containing the referral data.
     *
     * @return the buffer
     */
    public DfsReferralResponseBuffer getDfsResponse() {
        return this.dfsResponse;
    }

    @Override
    public boolean isForceUnicode() {
        return true;
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
        return 0;
    }

    @Override
    protected int readDataWireFormat(final byte[] buffer, int bufferIndex, final int len) {
        final int start = bufferIndex;
        bufferIndex += this.dfsResponse.decode(buffer, bufferIndex, len);
        return bufferIndex - start;
    }

    @Override
    public String toString() {
        return ("Trans2GetDfsReferralResponse[" + super.toString() + ",buffer=" + this.dfsResponse + "]");
    }
}
