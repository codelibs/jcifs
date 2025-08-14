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

package jcifs.internal.smb1.com;

import java.io.UnsupportedEncodingException;

import jcifs.Configuration;
import jcifs.internal.TreeConnectResponse;
import jcifs.internal.smb1.AndXServerMessageBlock;
import jcifs.internal.smb1.ServerMessageBlock;

/**
 *
 * @author mbechler
 *
 */
public class SmbComTreeConnectAndXResponse extends AndXServerMessageBlock implements TreeConnectResponse {

    private static final int SMB_SUPPORT_SEARCH_BITS = 0x0001;
    private static final int SMB_SHARE_IS_IN_DFS = 0x0002;

    private boolean supportSearchBits, shareIsInDfs;
    private String service;
    private String nativeFileSystem = "";

    /**
     *
     * @param config
     * @param andx
     */
    public SmbComTreeConnectAndXResponse(final Configuration config, final ServerMessageBlock andx) {
        super(config, andx);
    }

    /**
     * @return the service
     */
    @Override
    public final String getService() {
        return this.service;
    }

    /**
     * @return the nativeFileSystem
     */
    public final String getNativeFileSystem() {
        return this.nativeFileSystem;
    }

    /**
     * @return the supportSearchBits
     */
    public final boolean isSupportSearchBits() {
        return this.supportSearchBits;
    }

    /**
     * @return the shareIsInDfs
     */
    @Override
    public final boolean isShareDfs() {
        return this.shareIsInDfs;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.TreeConnectResponse#isValidTid()
     */
    @Override
    public boolean isValidTid() {
        return getTid() != 0xFFFF;
    }

    @Override
    protected int writeParameterWordsWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    protected int writeBytesWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    protected int readParameterWordsWireFormat(final byte[] buffer, final int bufferIndex) {
        this.supportSearchBits = (buffer[bufferIndex] & SMB_SUPPORT_SEARCH_BITS) == SMB_SUPPORT_SEARCH_BITS;
        this.shareIsInDfs = (buffer[bufferIndex] & SMB_SHARE_IS_IN_DFS) == SMB_SHARE_IS_IN_DFS;
        return 2;
    }

    @Override
    protected int readBytesWireFormat(final byte[] buffer, int bufferIndex) {
        final int start = bufferIndex;

        final int len = readStringLength(buffer, bufferIndex, 32);
        try {
            this.service = new String(buffer, bufferIndex, len, "ASCII");
        } catch (final UnsupportedEncodingException uee) {
            return 0;
        }
        bufferIndex += len + 1;
        // win98 observed not returning nativeFileSystem
        // Problems here with iSeries returning ASCII even though useUnicode = true
        // Fortunately we don't really need nativeFileSystem for anything.
        // However, we'll try to read it safely for compatibility
        if (this.byteCount > bufferIndex - start) {
            try {
                // Attempt to read nativeFileSystem, but don't fail if there are issues
                final int fsLen = this.byteCount - (bufferIndex - start);
                if (fsLen > 0 && fsLen < 256) { // Sanity check on length
                    this.nativeFileSystem = readString(buffer, bufferIndex);
                    bufferIndex += stringWireLength(this.nativeFileSystem, bufferIndex);
                }
            } catch (final Exception e) {
                // Ignore errors - some servers don't properly return this field
                // Keep the default empty string value
            }
        }

        return bufferIndex - start;
    }

    @Override
    public String toString() {
        return ("SmbComTreeConnectAndXResponse[" + super.toString() + ",supportSearchBits=" + this.supportSearchBits + ",shareIsInDfs="
                + this.shareIsInDfs + ",service=" + this.service + ",nativeFileSystem=" + this.nativeFileSystem + "]");
    }
}
