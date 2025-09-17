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
package org.codelibs.jcifs.smb.internal.smb2.info;

import java.util.ArrayList;
import java.util.List;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.impl.FileEntry;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.fscc.FileBothDirectoryInfo;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Response;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2 Query Directory response message. This response contains directory listing
 * information with file entries and their attributes.
 *
 * @author mbechler
 *
 */
public class Smb2QueryDirectoryResponse extends ServerMessageBlock2Response {

    /**
     * Protocol overhead size for SMB2 query directory response
     */
    public static final int OVERHEAD = Smb2Constants.SMB2_HEADER_LENGTH + 8;

    private final byte expectInfoClass;
    private FileEntry[] results;

    /**
     * Constructs a SMB2 query directory response with the specified configuration and expected information class
     *
     * @param config
     *            the configuration to use for this response
     * @param expectInfoClass
     *            the expected file information class in the response
     */
    public Smb2QueryDirectoryResponse(final Configuration config, final byte expectInfoClass) {
        super(config);
        this.expectInfoClass = expectInfoClass;
    }

    /**
     * Gets the directory entries returned by the query
     *
     * @return the fileInformation
     */
    public FileEntry[] getResults() {
        return this.results;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat(final byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException {
        final int start = bufferIndex;
        final int structureSize = SMBUtil.readInt2(buffer, bufferIndex);

        if (structureSize != 9) {
            throw new SMBProtocolDecodingException("Expected structureSize = 9");
        }

        final int bufferOffset = SMBUtil.readInt2(buffer, bufferIndex + 2) + getHeaderStart();
        bufferIndex += 4;
        final int bufferLength = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        // bufferIndex = bufferOffset;

        final List<FileEntry> infos = new ArrayList<>();
        do {
            final FileBothDirectoryInfo cur = createFileInfo();
            if (cur == null) {
                break;
            }
            cur.decode(buffer, bufferIndex, bufferLength);
            infos.add(cur);
            final int nextEntryOffset = cur.getNextEntryOffset();
            if (nextEntryOffset <= 0) {
                break;
            }
            bufferIndex += nextEntryOffset;
        } while (bufferIndex < bufferOffset + bufferLength);
        this.results = infos.toArray(new FileEntry[infos.size()]);
        return bufferIndex - start;
    }

    private FileBothDirectoryInfo createFileInfo() {
        if (this.expectInfoClass == Smb2QueryDirectoryRequest.FILE_BOTH_DIRECTORY_INFO) {
            return new FileBothDirectoryInfo(getConfig(), true);
        }
        return null;
    }

}
