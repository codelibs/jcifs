/* org.codelibs.jcifs.smb smb client library in Java
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
import org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransaction;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.codelibs.jcifs.smb.util.Hexdump;

/**
 * Trans2 FindNext2 request message for SMB1 directory enumeration continuation.
 * This class implements the TRANS2_FIND_NEXT2 transaction to retrieve subsequent
 * directory entries after a Trans2FindFirst2 request, supporting large directory listings.
 */
public class Trans2FindNext2 extends SmbComTransaction {

    private final int sid, informationLevel;
    private int resumeKey;
    private final int tflags;
    private String filename;
    private final long maxItems;

    /**
     * Constructs a Trans2FindNext2 request for continuing a file search.
     *
     * @param config the configuration to use
     * @param sid the search ID from a previous FindFirst2 response
     * @param resumeKey the resume key for continuing the search
     * @param filename the last filename from the previous response
     * @param batchCount the number of entries to return
     * @param batchSize the maximum size of the response buffer
     */
    public Trans2FindNext2(final Configuration config, final int sid, final int resumeKey, final String filename, final int batchCount,
            final int batchSize) {
        super(config, SMB_COM_TRANSACTION2, TRANS2_FIND_NEXT2);
        this.sid = sid;
        this.resumeKey = resumeKey;
        this.filename = filename;
        this.informationLevel = Trans2FindFirst2.SMB_FILE_BOTH_DIRECTORY_INFO;
        this.tflags = 0x00;
        this.maxParameterCount = 8;
        this.maxItems = batchCount;
        this.maxDataCount = batchSize;
        this.maxSetupCount = 0;
    }

    @Override
    public void reset(final int rk, final String lastName) {
        super.reset();
        this.resumeKey = rk;
        this.filename = lastName;
        this.flags2 = 0;
    }

    @Override
    protected int writeSetupWireFormat(final byte[] dst, int dstIndex) {
        dst[dstIndex] = getSubCommand();
        dstIndex++;
        dst[dstIndex++] = (byte) 0x00;
        return 2;
    }

    @Override
    protected int writeParametersWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        SMBUtil.writeInt2(this.sid, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.maxItems, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.informationLevel, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt4(this.resumeKey, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt2(this.tflags, dst, dstIndex);
        dstIndex += 2;
        dstIndex += writeString(this.filename, dst, dstIndex);

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
        return ("Trans2FindNext2[" + super.toString() + ",sid=" + this.sid + ",searchCount=" + getConfig().getListSize()
                + ",informationLevel=0x" + Hexdump.toHexString(this.informationLevel, 3) + ",resumeKey=0x"
                + Hexdump.toHexString(this.resumeKey, 4) + ",flags=0x" + Hexdump.toHexString(this.tflags, 2) + ",filename=" + this.filename
                + "]");
    }
}
