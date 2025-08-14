/* jcifs smb client library in Java
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

package jcifs.internal.smb1.trans2;

import jcifs.Configuration;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.smb1.trans.SmbComTransactionResponse;

/**
 *
 * @author mbechler
 *
 */
public class Trans2SetFileInformationResponse extends SmbComTransactionResponse {

    /**
     *
     * @param config
     */
    public Trans2SetFileInformationResponse(final Configuration config) {
        super(config);
        this.setSubCommand(SmbComTransaction.TRANS2_SET_FILE_INFORMATION);
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
    protected int readDataWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        return 0;
    }

    @Override
    public String toString() {
        return ("Trans2SetFileInformationResponse[" + super.toString() + "]");
    }
}
