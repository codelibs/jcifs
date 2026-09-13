/*
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
package org.codelibs.jcifs.smb.internal.smb2.create;

import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE, MS-SMB2 2.2.14.2.5.
 *
 * <p>
 * Carries the access the server grants this caller on the file it just opened.
 * QueryStatus is the result of computing it: a server that could not work the
 * access out reports the failure there and leaves MaximalAccess meaningless, so
 * both have to be read before the mask is used.
 * </p>
 */
public class QueryMaximalAccessResponse implements CreateContextResponse {

    static final byte[] NAME = { 'M', 'x', 'A', 'c' };

    private static final int RESPONSE_SIZE = 8;

    private int queryStatus;
    private int maximalAccess;

    /**
     * Constructs an empty response, to be filled in by decoding.
     */
    public QueryMaximalAccessResponse() {
    }

    @Override
    public byte[] getName() {
        return NAME.clone();
    }

    /**
     * Gets the status of the server's attempt to compute the access.
     *
     * @return NT_STATUS_SUCCESS when the mask is meaningful
     */
    public int getQueryStatus() {
        return this.queryStatus;
    }

    /**
     * Gets the access the server grants the caller on this file.
     *
     * @return an access mask, meaningful only when {@link #getQueryStatus()} is success
     */
    public int getMaximalAccess() {
        return this.maximalAccess;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Decodable#decode(byte[], int, int)
     */
    @Override
    public int decode(final byte[] buffer, int bufferIndex, final int len) throws SMBProtocolDecodingException {
        if (len < RESPONSE_SIZE) {
            throw new SMBProtocolDecodingException("Invalid maximal access response length " + len);
        }
        final int start = bufferIndex;
        this.queryStatus = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.maximalAccess = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        return bufferIndex - start;
    }
}
