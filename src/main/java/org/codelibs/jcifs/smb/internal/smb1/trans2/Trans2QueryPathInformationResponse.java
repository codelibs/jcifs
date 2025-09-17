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

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.fscc.FileBasicInfo;
import org.codelibs.jcifs.smb.internal.fscc.FileInformation;
import org.codelibs.jcifs.smb.internal.fscc.FileInternalInfo;
import org.codelibs.jcifs.smb.internal.fscc.FileStandardInfo;
import org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransaction;
import org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransactionResponse;

/**
 * Trans2 QueryPathInformation response message for file metadata queries.
 * This class handles the response from a TRANS2_QUERY_PATH_INFORMATION request,
 * returning various file information levels based on the requested information level.
 */
public class Trans2QueryPathInformationResponse extends SmbComTransactionResponse {

    private final int informationLevel;
    private FileInformation info;

    /**
     * Constructs a Trans2QueryPathInformationResponse with the specified configuration and information level.
     *
     * @param config the SMB configuration
     * @param informationLevel the file information level being queried
     */
    public Trans2QueryPathInformationResponse(final Configuration config, final int informationLevel) {
        super(config);
        this.informationLevel = informationLevel;
        this.setSubCommand(SmbComTransaction.TRANS2_QUERY_PATH_INFORMATION);
    }

    /**
     * Gets the file information from the response.
     *
     * @return the info
     */
    public final FileInformation getInfo() {
        return this.info;
    }

    /**
     * Gets the file information from the response cast to the specified type.
     *
     * @param <T> the type of file information to return
     * @param type the class of the file information to return
     * @return the info cast to the specified type
     * @throws CIFSException if the information cannot be cast to the specified type
     */
    @SuppressWarnings("unchecked")
    public <T extends FileInformation> T getInfo(final Class<T> type) throws CIFSException {
        if (!type.isAssignableFrom(this.info.getClass())) {
            throw new CIFSException("Incompatible file information class");
        }
        return (T) this.info;
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
        // observed two zero bytes here with at least win98
        return 2;
    }

    @Override
    protected int readDataWireFormat(final byte[] buffer, int bufferIndex, final int len) throws SMBProtocolDecodingException {
        final int start = bufferIndex;
        final FileInformation inf = createFileInformation();
        if (inf != null) {
            bufferIndex += inf.decode(buffer, bufferIndex, getDataCount());
            this.info = inf;
        }
        return bufferIndex - start;
    }

    private FileInformation createFileInformation() {
        FileInformation inf;
        switch (this.informationLevel) {
        case FileInformation.FILE_BASIC_INFO:
            inf = new FileBasicInfo();
            break;
        case FileInformation.FILE_STANDARD_INFO:
            inf = new FileStandardInfo();
            break;
        case FileInformation.FILE_INTERNAL_INFO:
            inf = new FileInternalInfo();
            break;
        default:
            return null;
        }
        return inf;
    }

    @Override
    public String toString() {
        return ("Trans2QueryPathInformationResponse[" + super.toString() + "]");
    }
}
