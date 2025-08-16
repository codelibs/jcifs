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

package jcifs.internal.smb1.trans;

import jcifs.Configuration;
import jcifs.internal.SMBProtocolDecodingException;

/**
 * Response for SMB1 TRANS_CALL_NAMED_PIPE transaction.
 *
 * This response contains the data returned from the named pipe
 * after a call transaction has been processed by the server.
 */
public class TransCallNamedPipeResponse extends SmbComTransactionResponse {

    private final byte[] outputBuffer;

    /**
     * Constructs a TransCallNamedPipeResponse with the specified configuration and output buffer.
     *
     * @param config the SMB configuration
     * @param inB the buffer to receive response data from the named pipe
     */
    public TransCallNamedPipeResponse(final Configuration config, final byte[] inB) {
        super(config);
        this.outputBuffer = inB;
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
        return 0;
    }

    @Override
    protected int readDataWireFormat(final byte[] buffer, final int bufferIndex, final int len) throws SMBProtocolDecodingException {
        if (len > this.outputBuffer.length) {
            throw new SMBProtocolDecodingException("Payload exceeds buffer size");
        }
        System.arraycopy(buffer, bufferIndex, this.outputBuffer, 0, len);
        return len;
    }

    @Override
    public String toString() {
        return ("TransCallNamedPipeResponse[" + super.toString() + "]");
    }

    /**
     * Gets the length of the response data received from the named pipe.
     *
     * @return response data length
     */
    public int getResponseLength() {
        return getDataCount();
    }
}
