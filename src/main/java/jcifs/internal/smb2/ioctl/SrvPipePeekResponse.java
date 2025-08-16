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
 * Response structure for SMB2 IOCTL pipe peek operation.
 * Provides information about data available in a named pipe.
 *
 * @author svella
 *
 */
public class SrvPipePeekResponse implements Decodable {

    /**
     * Constructs a new SrvPipePeekResponse.
     * This response contains information about data available in a named pipe.
     */
    public SrvPipePeekResponse() {
    }

    // see https://msdn.microsoft.com/en-us/library/dd414577.aspx

    private int namedPipeState;
    private int readDataAvailable;
    private int numberOfMessages;
    private int messageLength;
    private byte[] data;

    /**
     * Gets the current state of the named pipe
     * @return the namedPipeState
     */
    public int getNamedPipeState() {
        return this.namedPipeState;
    }

    /**
     * Gets the amount of data available to read from the pipe
     * @return the readDataAvailable
     */
    public int getReadDataAvailable() {
        return this.readDataAvailable;
    }

    /**
     * Gets the number of messages available in the pipe
     * @return the numberOfMessages
     */
    public int getNumberOfMessages() {
        return this.numberOfMessages;
    }

    /**
     * Gets the length of the first message in the pipe
     * @return the messageLength
     */
    public int getMessageLength() {
        return this.messageLength;
    }

    /**
     * Gets the data peeked from the pipe
     * @return the data
     */
    public byte[] getData() {
        return this.data;
    }

    /**
     * {@inheritDoc}
     *
     * @see Decodable#decode(byte[], int, int)
     */
    @Override
    public int decode(final byte[] buffer, int bufferIndex, final int len) throws SMBProtocolDecodingException {
        final int start = bufferIndex;
        this.namedPipeState = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.readDataAvailable = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.numberOfMessages = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.messageLength = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.data = new byte[len - 16];
        if (this.data.length > 0) {
            System.arraycopy(buffer, bufferIndex, this.data, 0, this.data.length);
        }
        return bufferIndex - start;
    }

}
