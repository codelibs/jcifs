/* org.codelibs.jcifs.smb smb client library in Java
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
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest;
import org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransaction;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * Base class for SMB1 NT Transaction request messages.
 *
 * NT Transactions are an extended form of the basic transaction protocol
 * that provides additional functionality for Windows NT-specific operations
 * such as security descriptor queries and file change notifications.
 */
public abstract class SmbComNtTransaction extends SmbComTransaction {

    // relative to headerStart
    private static final int NTT_PRIMARY_SETUP_OFFSET = 71;
    private static final int NTT_SECONDARY_PARAMETER_OFFSET = 51;

    /**
     * NT transaction function code for querying security descriptors.
     * Used to retrieve security information about a file or directory.
     */
    public static final int NT_TRANSACT_QUERY_SECURITY_DESC = 0x6;

    /**
     * NT transaction function code for change notification.
     * Used to monitor changes to a directory or file.
     */
    public static final int NT_TRANSACT_NOTIFY_CHANGE = 0x4;

    private final int function;

    /**
     * Constructs an NT transaction command.
     *
     * @param config the configuration
     * @param function the NT transaction function code
     */
    protected SmbComNtTransaction(final Configuration config, final int function) {
        super(config, SMB_COM_NT_TRANSACT, (byte) 0);
        this.function = function;
        this.primarySetupOffset = NTT_PRIMARY_SETUP_OFFSET;
        this.secondaryParameterOffset = NTT_SECONDARY_PARAMETER_OFFSET;
    }

    /**
     *
     * @return a cancel request
     */
    @Override
    public CommonServerMessageBlockRequest createCancel() {
        return new SmbComNtCancel(getConfig(), (int) getMid());
    }

    @Override
    protected int writeParameterWordsWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        if (this.getCommand() != SMB_COM_NT_TRANSACT_SECONDARY) {
            dst[dstIndex++] = this.maxSetupCount;
        } else {
            dst[dstIndex++] = (byte) 0x00; // Reserved
        }
        dst[dstIndex] = (byte) 0x00; // Reserved
        dstIndex++;
        dst[dstIndex++] = (byte) 0x00; // Reserved
        SMBUtil.writeInt4(this.totalParameterCount, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.totalDataCount, dst, dstIndex);
        dstIndex += 4;
        if (this.getCommand() != SMB_COM_NT_TRANSACT_SECONDARY) {
            SMBUtil.writeInt4(this.maxParameterCount, dst, dstIndex);
            dstIndex += 4;
            SMBUtil.writeInt4(this.maxDataCount, dst, dstIndex);
            dstIndex += 4;
        }
        SMBUtil.writeInt4(this.parameterCount, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.parameterCount == 0 ? 0 : this.parameterOffset, dst, dstIndex);
        dstIndex += 4;
        if (this.getCommand() == SMB_COM_NT_TRANSACT_SECONDARY) {
            SMBUtil.writeInt4(this.parameterDisplacement, dst, dstIndex);
            dstIndex += 4;
        }
        SMBUtil.writeInt4(this.dataCount, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.dataCount == 0 ? 0 : this.dataOffset, dst, dstIndex);
        dstIndex += 4;
        if (this.getCommand() == SMB_COM_NT_TRANSACT_SECONDARY) {
            SMBUtil.writeInt4(this.dataDisplacement, dst, dstIndex);
            dstIndex += 4;
            dst[dstIndex++] = (byte) 0x00; // Reserved1
        } else {
            dst[dstIndex++] = (byte) this.setupCount;
            SMBUtil.writeInt2(this.function, dst, dstIndex);
            dstIndex += 2;
            dstIndex += writeSetupWireFormat(dst, dstIndex);
        }

        return dstIndex - start;
    }
}
