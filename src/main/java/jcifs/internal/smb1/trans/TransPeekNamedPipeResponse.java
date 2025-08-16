/* jcifs smb client library in Java
 * Copyright (C) 2002  "Michael B. Allen" <jcifs at samba dot org>
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

package jcifs.internal.smb1.trans;

import jcifs.Configuration;
import jcifs.internal.util.SMBUtil;

/**
 * Response for SMB1 TRANS_PEEK_NAMED_PIPE transaction.
 *
 * This response contains information about the data available in the
 * named pipe without actually removing the data from the pipe.
 */
public class TransPeekNamedPipeResponse extends SmbComTransactionResponse {

    /**
     * Named pipe status indicating the pipe is disconnected.
     */
    public static final int STATUS_DISCONNECTED = 1;

    /**
     * Named pipe status indicating the pipe is listening for connections.
     */
    public static final int STATUS_LISTENING = 2;

    /**
     * Named pipe status indicating the connection is established and operational.
     */
    public static final int STATUS_CONNECTION_OK = 3;

    /**
     * Named pipe status indicating the server end of the pipe is closed.
     */
    public static final int STATUS_SERVER_END_CLOSED = 4;

    private int available;

    /**
     * Constructs a TransPeekNamedPipeResponse with the specified configuration.
     *
     * @param config the SMB configuration
     */
    public TransPeekNamedPipeResponse(final Configuration config) {
        super(config);
    }

    /**
     * Gets the number of bytes available to read from the named pipe.
     *
     * @return the available
     */
    public final int getAvailable() {
        return this.available;
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
        this.available = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        setStatus(SMBUtil.readInt2(buffer, bufferIndex));
        return 6;
    }

    @Override
    protected int readDataWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        return 0;
    }

    @Override
    public String toString() {
        return ("TransPeekNamedPipeResponse[" + super.toString() + "]");
    }
}
