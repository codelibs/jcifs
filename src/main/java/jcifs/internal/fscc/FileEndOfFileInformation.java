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
package jcifs.internal.fscc;

import jcifs.Encodable;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;

/**
 * File System Control Code (FSCC) structure for File End-of-File Information.
 * Used in SMB2/SMB3 operations to set or query the end-of-file position for a file,
 * effectively controlling file size truncation or extension.
 *
 * @author mbechler
 */
public class FileEndOfFileInformation implements FileInformation, Encodable {

    private long endOfFile;

    /**
     * Default constructor for decoding.
     */
    public FileEndOfFileInformation() {
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.fscc.FileInformation#getFileInformationLevel()
     */
    @Override
    public byte getFileInformationLevel() {
        return FileInformation.FILE_ENDOFFILE_INFO;
    }

    /**
     * Constructs file end of file information.
     *
     * @param eofOfFile the end of file position
     */
    public FileEndOfFileInformation(final long eofOfFile) {
        this.endOfFile = eofOfFile;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Decodable#decode(byte[], int, int)
     */
    @Override
    public int decode(final byte[] buffer, final int bufferIndex, final int len) throws SMBProtocolDecodingException {
        this.endOfFile = SMBUtil.readInt8(buffer, bufferIndex);
        return 8;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#size()
     */
    @Override
    public int size() {
        return 8;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#encode(byte[], int)
     */
    @Override
    public int encode(final byte[] dst, final int dstIndex) {
        SMBUtil.writeInt8(this.endOfFile, dst, dstIndex);
        return 8;
    }

    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return ("EndOfFileInformation[endOfFile=" + this.endOfFile + "]");
    }

}
