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
package org.codelibs.jcifs.smb.internal;

import org.codelibs.jcifs.smb.util.transport.Message;

/**
 * Common interface for all SMB message blocks in the jCIFS protocol implementation.
 * Provides core functionality for encoding/decoding SMB messages, handling message signing,
 * and managing message metadata such as IDs, commands, and authentication information.
 *
 * @author mbechler
 */
public interface CommonServerMessageBlock extends Message {

    /**
     * Decode message data from the given byte array
     *
     * @param buffer the byte array containing the message data
     * @param bufferIndex the starting index in the buffer
     * @return message length
     * @throws SMBProtocolDecodingException if decoding fails
     */
    int decode(byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException;

    /**
     * Encodes this message into a byte array.
     *
     * @param dst the destination byte array
     * @param dstIndex the starting index in the destination array
     * @return message length
     */
    int encode(byte[] dst, int dstIndex);

    /**
     * Sets the signing digest for this message.
     *
     * @param digest the signing digest to set
     */
    void setDigest(SMBSigningDigest digest);

    /**
     * Gets the signing digest for this message.
     *
     * @return the signing digest
     */
    SMBSigningDigest getDigest();

    /**
     * Gets the response associated with this message.
     *
     * @return the associated response
     */
    CommonServerMessageBlockResponse getResponse();

    /**
     * Sets the response for this message.
     *
     * @param msg the response message to set
     */
    void setResponse(CommonServerMessageBlockResponse msg);

    /**
     * Gets the message ID.
     *
     * @return the message id
     */
    long getMid();

    /**
     * Sets the message ID.
     *
     * @param mid the message ID to set
     */
    void setMid(long mid);

    /**
     * Gets the SMB command.
     *
     * @return the command
     */
    int getCommand();

    /**
     * Sets the SMB command.
     *
     * @param command the command to set
     */
    void setCommand(int command);

    /**
     * Sets the user ID.
     *
     * @param uid the user ID to set
     */
    void setUid(int uid);

    /**
     * Sets whether extended security is enabled.
     *
     * @param extendedSecurity true to enable extended security
     */
    void setExtendedSecurity(boolean extendedSecurity);

    /**
     * Sets the session ID.
     *
     * @param sessionId the session ID to set
     */
    void setSessionId(long sessionId);

    /**
     * Resets this message to its initial state.
     */
    void reset();

}
