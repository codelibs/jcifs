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
import jcifs.internal.fscc.FileSystemInformation;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;

/**
 * Trans2 QueryFSInformation request message for querying file system information.
 * This class implements the TRANS2_QUERY_FS_INFORMATION transaction to retrieve
 * various file system attributes such as volume information, size, and capabilities.
 */
public class Trans2QueryFSInformation extends SmbComTransaction {

    private final int informationLevel;

    /**
     * Constructs a Trans2QueryFSInformation request.
     *
     * @param config the SMB configuration
     * @param informationLevel the file system information level to query
     */
    public Trans2QueryFSInformation(final Configuration config, final int informationLevel) {
        super(config, SMB_COM_TRANSACTION2, TRANS2_QUERY_FS_INFORMATION);
        this.informationLevel = informationLevel;
        this.totalParameterCount = 2;
        this.totalDataCount = 0;
        this.maxParameterCount = 0;
        this.maxDataCount = 800;
        this.maxSetupCount = 0;
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

        SMBUtil.writeInt2(mapInformationLevel(this.informationLevel), dst, dstIndex);
        dstIndex += 2;

        /*
         * windows98 has what appears to be another 4 0's followed by the share
         * name as a zero terminated ascii string "\TMP" + '\0'
         *
         * As is this works, but it deviates from the spec section 4.1.6.6 but
         * maybe I should put it in. Wonder what NT does?
         */

        return dstIndex - start;
    }

    /**
     * @param il
     * @return
     */
    private static int mapInformationLevel(final int il) {
        switch (il) {
        case FileSystemInformation.SMB_INFO_ALLOCATION:
            return 0x1;
        case FileSystemInformation.FS_SIZE_INFO:
            return 0x103;
        }
        throw new IllegalArgumentException("Unhandled information level");
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
        return ("Trans2QueryFSInformation[" + super.toString() + ",informationLevel=0x" + Hexdump.toHexString(this.informationLevel, 3)
                + "]");
    }
}
