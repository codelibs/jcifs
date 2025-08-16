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
package jcifs.internal.smb2.ioctl;

import jcifs.Decodable;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;

/**
 * SMB2 Validate Negotiate Info response data structure. This structure contains the server's
 * validation of the originally negotiated SMB2 dialect.
 *
 * @author mbechler
 *
 */
public class ValidateNegotiateInfoResponse implements Decodable {

    /**
     * Default constructor for ValidateNegotiateInfoResponse
     */
    public ValidateNegotiateInfoResponse() {
        // Default constructor
    }

    private int capabilities;
    private final byte[] serverGuid = new byte[16];
    private int securityMode;
    private int dialect;

    /**
     * Gets the server capabilities
     *
     * @return the capabilities flags from the server
     */
    public int getCapabilities() {
        return this.capabilities;
    }

    /**
     * Gets the server GUID
     *
     * @return the server's unique identifier
     */
    public byte[] getServerGuid() {
        return this.serverGuid;
    }

    /**
     * Gets the security mode
     *
     * @return the security mode flags from the server
     */
    public int getSecurityMode() {
        return this.securityMode;
    }

    /**
     * Gets the negotiated SMB dialect
     *
     * @return the SMB dialect negotiated with the server
     */
    public int getDialect() {
        return this.dialect;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Decodable#decode(byte[], int, int)
     */
    @Override
    public int decode(final byte[] buffer, int bufferIndex, final int len) throws SMBProtocolDecodingException {
        final int start = bufferIndex;

        this.capabilities = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        System.arraycopy(buffer, bufferIndex, this.serverGuid, 0, 16);
        bufferIndex += 16;

        this.securityMode = SMBUtil.readInt2(buffer, bufferIndex);
        this.dialect = SMBUtil.readInt2(buffer, bufferIndex + 2);
        bufferIndex += 4;

        return bufferIndex - start;
    }

}
