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

import java.util.Arrays;

/**
 * SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST, MS-SMB2 2.2.13.2.5.
 *
 * <p>
 * Asks the server to report, in the create response, the access it would grant
 * this caller on the file being opened. That answer accounts for the share and
 * for the file's own permissions, neither of which the file attributes carry.
 * </p>
 *
 * <p>
 * The Timestamp the structure may carry is sent as zero. A server is allowed to
 * skip the response when the file has not changed since the timestamp given, and
 * zero is never a file's last write time, so a zero timestamp is the form that is
 * always answered.
 * </p>
 */
public class QueryMaximalAccessRequest implements CreateContextRequest {

    static final byte[] NAME = { 'M', 'x', 'A', 'c' };

    private static final int TIMESTAMP_SIZE = 8;

    /**
     * Constructs a request for the caller's maximal access on the file.
     */
    public QueryMaximalAccessRequest() {
    }

    @Override
    public byte[] getName() {
        return NAME.clone();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Encodable#encode(byte[], int)
     */
    @Override
    public int encode(final byte[] dst, final int dstIndex) {
        // Written rather than assumed: the transport buffer is reused, so what is
        // already at this offset is whatever the previous message left there.
        Arrays.fill(dst, dstIndex, dstIndex + TIMESTAMP_SIZE, (byte) 0);
        return TIMESTAMP_SIZE;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Encodable#size()
     */
    @Override
    public int size() {
        return TIMESTAMP_SIZE;
    }
}
