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

package org.codelibs.jcifs.smb.internal.smb1.trans2;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransaction;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.codelibs.jcifs.smb.util.Hexdump;

/**
 * SMB1 Trans2 Find First 2 transaction request implementation.
 * Initiates directory enumeration operations in SMB1 protocol, allowing clients
 * to search for files and directories matching specified patterns and criteria.
 *
 * @author mbechler
 */
public class Trans2FindFirst2 extends SmbComTransaction {

    // flags

    static final int FLAGS_CLOSE_AFTER_THIS_REQUEST = 0x01;
    static final int FLAGS_CLOSE_IF_END_REACHED = 0x02;
    static final int FLAGS_RETURN_RESUME_KEYS = 0x04;
    static final int FLAGS_RESUME_FROM_PREVIOUS_END = 0x08;
    static final int FLAGS_FIND_WITH_BACKUP_INTENT = 0x10;

    private final int searchAttributes;
    private final int tflags;
    private final int informationLevel;
    private final int searchStorageType = 0;
    private final int maxItems;
    private final String wildcard;

    // information levels

    static final int SMB_INFO_STANDARD = 1;
    static final int SMB_INFO_QUERY_EA_SIZE = 2;
    static final int SMB_INFO_QUERY_EAS_FROM_LIST = 3;
    static final int SMB_FIND_FILE_DIRECTORY_INFO = 0x101;
    static final int SMB_FIND_FILE_FULL_DIRECTORY_INFO = 0x102;
    static final int SMB_FILE_NAMES_INFO = 0x103;
    static final int SMB_FILE_BOTH_DIRECTORY_INFO = 0x104;

    /**
     * Constructs a Trans2FindFirst2 request for finding files.
     *
     * @param config the configuration to use
     * @param filename the path to search in
     * @param wildcard the wildcard pattern to match
     * @param searchAttributes the file attributes to search for
     * @param batchCount the number of entries to return
     * @param batchSize the maximum size of the response buffer
     */
    public Trans2FindFirst2(final Configuration config, final String filename, final String wildcard, final int searchAttributes,
            final int batchCount, final int batchSize) {
        super(config, SMB_COM_TRANSACTION2, TRANS2_FIND_FIRST2);
        if (filename.equals("\\") || (filename.charAt(filename.length() - 1) == '\\')) {
            this.path = filename;
        } else {
            this.path = filename + "\\";
        }
        this.wildcard = wildcard;
        this.searchAttributes = searchAttributes & 0x37; /* generally ignored tho */

        this.tflags = 0x00;
        this.informationLevel = SMB_FILE_BOTH_DIRECTORY_INFO;

        this.totalDataCount = 0;
        this.maxParameterCount = 10;
        this.maxItems = batchCount;
        this.maxDataCount = batchSize;
        this.maxSetupCount = 0;
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

        SMBUtil.writeInt2(this.searchAttributes, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.maxItems, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.tflags, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.informationLevel, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt4(this.searchStorageType, dst, dstIndex);
        dstIndex += 4;
        dstIndex += writeString(this.path + this.wildcard, dst, dstIndex);

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
        return ("Trans2FindFirst2[" + super.toString() + ",searchAttributes=0x" + Hexdump.toHexString(this.searchAttributes, 2)
                + ",searchCount=" + this.maxItems + ",flags=0x" + Hexdump.toHexString(this.tflags, 2) + ",informationLevel=0x"
                + Hexdump.toHexString(this.informationLevel, 3) + ",searchStorageType=" + this.searchStorageType + ",filename=" + this.path
                + "]");
    }
}
