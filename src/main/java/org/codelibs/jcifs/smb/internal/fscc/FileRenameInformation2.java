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

import java.nio.charset.StandardCharsets;

import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * File System Control Code (FSCC) structure for File Rename Information.
 * Used in SMB2/SMB3 set file information operations to rename files or directories,
 * with support for specifying whether to replace existing files with the same name.
 *
 * @author mbechler
 */
public class FileRenameInformation2 implements FileInformation {

    private boolean replaceIfExists;
    private String fileName;

    /**
     * Default constructor for decoding.
     */
    public FileRenameInformation2() {
    }

    /**
     * Constructs file rename information.
     *
     * @param name the new file name
     * @param replaceIfExists whether to replace if the target file exists
     */
    public FileRenameInformation2(final String name, final boolean replaceIfExists) {
        this.fileName = name;
        this.replaceIfExists = replaceIfExists;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Decodable#decode(byte[], int, int)
     */
    @Override
    public int decode(final byte[] buffer, int bufferIndex, final int len) throws SMBProtocolDecodingException {
        final int start = bufferIndex;
        this.replaceIfExists = buffer[bufferIndex] != 0;
        bufferIndex += 8;
        bufferIndex += 8;

        final int nameLen = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        final byte[] nameBytes = new byte[nameLen];
        System.arraycopy(buffer, bufferIndex, nameBytes, 0, nameBytes.length);
        bufferIndex += nameLen;
        this.fileName = new String(nameBytes, StandardCharsets.UTF_16LE);
        return bufferIndex - start;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Encodable#encode(byte[], int)
     */
    @Override
    public int encode(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        dst[dstIndex] = (byte) (this.replaceIfExists ? 1 : 0);
        dstIndex += 8; // 7 Reserved
        dstIndex += 8; // RootDirectory = 0

        final byte[] nameBytes = this.fileName.getBytes(StandardCharsets.UTF_16LE);

        SMBUtil.writeInt4(nameBytes.length, dst, dstIndex);
        dstIndex += 4;

        System.arraycopy(nameBytes, 0, dst, dstIndex, nameBytes.length);
        dstIndex += nameBytes.length;

        return dstIndex - start;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Encodable#size()
     */
    @Override
    public int size() {
        return 20 + 2 * this.fileName.length();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.fscc.FileInformation#getFileInformationLevel()
     */
    @Override
    public byte getFileInformationLevel() {
        return FileInformation.FILE_RENAME_INFO;
    }

}
