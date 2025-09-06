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
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.fscc.FileBothDirectoryInfo;
import org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransaction;
import org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransactionResponse;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * Trans2 FindFirst2 response message for SMB1 directory enumeration.
 * This class handles the response from a TRANS2_FIND_FIRST2 request, which returns
 * the first set of directory entries matching the specified search criteria.
 */
public class Trans2FindFirst2Response extends SmbComTransactionResponse {

    // information levels

    static final int SMB_INFO_STANDARD = 1;
    static final int SMB_INFO_QUERY_EA_SIZE = 2;
    static final int SMB_INFO_QUERY_EAS_FROM_LIST = 3;
    static final int SMB_FIND_FILE_DIRECTORY_INFO = 0x101;
    static final int SMB_FIND_FILE_FULL_DIRECTORY_INFO = 0x102;
    static final int SMB_FILE_NAMES_INFO = 0x103;
    static final int SMB_FILE_BOTH_DIRECTORY_INFO = 0x104;

    private int sid;
    private boolean isEndOfSearch;
    private int eaErrorOffset;
    private int lastNameOffset;
    private String lastName;
    private int resumeKey;

    /**
     * Constructs a Trans2FindFirst2Response.
     *
     * @param config the configuration to use
     */
    public Trans2FindFirst2Response(final Configuration config) {
        super(config, SMB_COM_TRANSACTION2, SmbComTransaction.TRANS2_FIND_FIRST2);
    }

    /**
     * Gets the search ID for this response.
     *
     * @return the sid
     */
    public final int getSid() {
        return this.sid;
    }

    /**
     * Checks if this is the end of the search results.
     *
     * @return the isEndOfSearch
     */
    public final boolean isEndOfSearch() {
        return this.isEndOfSearch;
    }

    /**
     * Gets the last file name in the response.
     *
     * @return the lastName
     */
    public final String getLastName() {
        return this.lastName;
    }

    /**
     * Gets the resume key for continuing the search.
     *
     * @return the resumeKey
     */
    public final int getResumeKey() {
        return this.resumeKey;
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
    protected int readParametersWireFormat(final byte[] buffer, int bufferIndex, final int len) {
        final int start = bufferIndex;

        if (this.getSubCommand() == SmbComTransaction.TRANS2_FIND_FIRST2) {
            this.sid = SMBUtil.readInt2(buffer, bufferIndex);
            bufferIndex += 2;
        }
        this.setNumEntries(SMBUtil.readInt2(buffer, bufferIndex));
        bufferIndex += 2;
        this.isEndOfSearch = ((buffer[bufferIndex] & 0x01) == 0x01) == true;
        bufferIndex += 2;
        this.eaErrorOffset = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.lastNameOffset = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;

        return bufferIndex - start;
    }

    @Override
    protected int readDataWireFormat(final byte[] buffer, int bufferIndex, final int len) throws SMBProtocolDecodingException {
        FileBothDirectoryInfo e;

        int lastNameBufferIndex = bufferIndex + this.lastNameOffset;

        final FileBothDirectoryInfo[] results = new FileBothDirectoryInfo[getNumEntries()];
        for (int i = 0; i < getNumEntries(); i++) {
            results[i] = e = new FileBothDirectoryInfo(getConfig(), isUseUnicode());

            e.decode(buffer, bufferIndex, len);

            /*
             * lastNameOffset ends up pointing to either to
             * the exact location of the filename(e.g. Win98)
             * or to the start of the entry containing the
             * filename(e.g. NT). Ahhrg! In either case the
             * lastNameOffset falls between the start of the
             * entry and the next entry.
             */

            if (lastNameBufferIndex >= bufferIndex
                    && (e.getNextEntryOffset() == 0 || lastNameBufferIndex < bufferIndex + e.getNextEntryOffset())) {
                this.lastName = e.getFilename();
                this.resumeKey = e.getFileIndex();
            }

            bufferIndex += e.getNextEntryOffset();
        }

        setResults(results);

        /*
         * last nextEntryOffset for NT 4(but not 98) is 0 so we must
         * use dataCount or our accounting will report an error for NT :~(
         */
        return getDataCount();
    }

    @Override
    public String toString() {
        String c;
        if (this.getSubCommand() == SmbComTransaction.TRANS2_FIND_FIRST2) {
            c = "Trans2FindFirst2Response[";
        } else {
            c = "Trans2FindNext2Response[";
        }
        return (c + super.toString() + ",sid=" + this.sid + ",searchCount=" + getNumEntries() + ",isEndOfSearch=" + this.isEndOfSearch
                + ",eaErrorOffset=" + this.eaErrorOffset + ",lastNameOffset=" + this.lastNameOffset + ",lastName=" + this.lastName + "]");
    }
}
