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

package jcifs.internal.smb1.trans.nt;

import jcifs.Configuration;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;

/**
 * SMB1 NT Transaction subcommand for file system change notification.
 *
 * This transaction allows monitoring of file system changes in a directory,
 * such as file creation, modification, deletion, and attribute changes.
 */
public class NtTransNotifyChange extends SmbComNtTransaction {

    int fid;
    private final int completionFilter;
    private final boolean watchTree;

    /**
     * Constructs an NT transaction for change notification monitoring.
     * @param config the configuration context
     * @param fid the file identifier to monitor
     * @param completionFilter bitmask specifying the types of changes to monitor
     * @param watchTree true to monitor the entire directory tree, false for directory only
     */
    public NtTransNotifyChange(final Configuration config, final int fid, final int completionFilter, final boolean watchTree) {
        super(config, NT_TRANSACT_NOTIFY_CHANGE);
        this.fid = fid;
        this.completionFilter = completionFilter;
        this.watchTree = watchTree;
        this.setupCount = 0x04;
        this.totalDataCount = 0;
        this.maxDataCount = 0;
        this.maxParameterCount = config.getNotifyBufferSize();
        this.maxSetupCount = (byte) 0x00;
    }

    @Override
    protected int writeSetupWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        SMBUtil.writeInt4(this.completionFilter, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt2(this.fid, dst, dstIndex);
        dstIndex += 2;
        dst[dstIndex] = this.watchTree ? (byte) 0x01 : (byte) 0x00; // watchTree
        dstIndex++;
        dst[dstIndex++] = (byte) 0x00; // Reserved
        return dstIndex - start;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb1.trans.SmbComTransaction#writeParametersWireFormat(byte[], int)
     */
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
        return ("NtTransNotifyChange[" + super.toString() + ",fid=0x" + Hexdump.toHexString(this.fid, 4) + ",filter=0x"
                + Hexdump.toHexString(this.completionFilter, 4) + ",watchTree=" + this.watchTree + "]");
    }
}
