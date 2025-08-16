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
import jcifs.internal.fscc.FileInformation;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;

/**
 * Trans2 QueryPathInformation request message for querying file metadata.
 * This class implements the TRANS2_QUERY_PATH_INFORMATION transaction to retrieve
 * various file information levels such as basic info, standard info, and attributes.
 */
public class Trans2QueryPathInformation extends SmbComTransaction {

    private final int informationLevel;

    /**
     * Constructs a Trans2QueryPathInformation request.
     *
     * @param config the SMB configuration
     * @param filename the path to query information for
     * @param informationLevel the information level to query
     */
    public Trans2QueryPathInformation(final Configuration config, final String filename, final int informationLevel) {
        super(config, SMB_COM_TRANSACTION2, TRANS2_QUERY_PATH_INFORMATION);
        this.path = filename;
        this.informationLevel = informationLevel;
        this.totalDataCount = 0;
        this.maxParameterCount = 2;
        this.maxDataCount = 40;
        this.maxSetupCount = (byte) 0x00;
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
        dst[dstIndex] = (byte) 0x00;
        dstIndex++;
        dst[dstIndex++] = (byte) 0x00;
        dst[dstIndex++] = (byte) 0x00;
        dst[dstIndex++] = (byte) 0x00;
        dstIndex += writeString(this.path, dst, dstIndex);

        return dstIndex - start;
    }

    /**
     * @param informationLevel2
     * @return
     */
    static long mapInformationLevel(final int il) {
        switch (il) {
        case FileInformation.FILE_BASIC_INFO:
            return 0x0101;
        case FileInformation.FILE_STANDARD_INFO:
            return 0x0102;
        case FileInformation.FILE_ENDOFFILE_INFO:
            return 0x0104;
        }
        throw new IllegalArgumentException("Unsupported information level " + il);
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
        return ("Trans2QueryPathInformation[" + super.toString() + ",informationLevel=0x" + Hexdump.toHexString(this.informationLevel, 3)
                + ",filename=" + this.path + "]");
    }
}
