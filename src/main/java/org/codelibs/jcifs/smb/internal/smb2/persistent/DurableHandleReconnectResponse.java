/*
 * © 2025 CodeLibs, Inc.
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
 */
package org.codelibs.jcifs.smb.internal.smb2.persistent;

import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.smb2.create.CreateContextResponse;

/**
 * SMB2 Durable Handle Reconnect Response Create Context
 *
 * MS-SMB2 Section 2.2.14.2.5
 */
public class DurableHandleReconnectResponse implements CreateContextResponse {

    /**
     * Context name for durable handle reconnect response
     */
    public static final String CONTEXT_NAME = "DHnC";

    private static final byte[] CONTEXT_NAME_BYTES = CONTEXT_NAME.getBytes();

    // The response structure is empty (0 bytes) for reconnect
    // No data is returned in a successful reconnect response

    /**
     * Create a new durable handle reconnect response
     */
    public DurableHandleReconnectResponse() {
        // No data fields for reconnect response
    }

    @Override
    public byte[] getName() {
        return CONTEXT_NAME_BYTES;
    }

    @Override
    public int decode(byte[] buffer, int bufferIndex, int len) throws SMBProtocolDecodingException {
        // Reconnect response has no data - length should be 0
        if (len != 0) {
            throw new SMBProtocolDecodingException("Invalid durable handle reconnect response length: " + len);
        }

        // No data to decode
        return 0;
    }

    /**
     * Get the context name as string
     * @return the context name
     */
    public String getContextName() {
        return CONTEXT_NAME;
    }
}
