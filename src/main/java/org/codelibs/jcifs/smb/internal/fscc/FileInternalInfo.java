/*
 * © 2017 AgNO3 Gmbh & Co. KG
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
package org.codelibs.jcifs.smb.internal.fscc;

import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * File System Control Code (FSCC) structure for File Internal Information.
 * Provides access to the file's internal index number, which is a unique identifier
 * assigned by the file system for internal tracking and reference purposes.
 *
 * @author mbechler
 */
public class FileInternalInfo implements FileInformation {

    private long indexNumber;

    /**
     * Default constructor for decoding file internal information.
     */
    public FileInternalInfo() {
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.fscc.FileInformation#getFileInformationLevel()
     */
    @Override
    public byte getFileInformationLevel() {
        return FILE_INTERNAL_INFO;
    }

    /**
     * Gets the file index number.
     *
     * @return the index number assigned by the file system
     */
    public long getIndexNumber() {
        return this.indexNumber;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Decodable#decode(byte[], int, int)
     */
    @Override
    public int decode(final byte[] buffer, final int bufferIndex, final int len) throws SMBProtocolDecodingException {
        this.indexNumber = SMBUtil.readInt8(buffer, bufferIndex);
        return 8;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Encodable#size()
     */
    @Override
    public int size() {
        return 8;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Encodable#encode(byte[], int)
     */
    @Override
    public int encode(final byte[] dst, final int dstIndex) {
        SMBUtil.writeInt8(this.indexNumber, dst, dstIndex);
        return 8;
    }

    @Override
    public String toString() {
        return ("SmbQueryFileInternalInfo[" + "indexNumber=" + this.indexNumber + "]");
    }
}