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
package jcifs.internal.smb2.persistent;

import jcifs.internal.smb2.create.CreateContextResponse;
import jcifs.internal.SMBProtocolDecodingException;

/**
 * SMB2 Durable Handle Response Create Context
 *
 * MS-SMB2 Section 2.2.14.2.3
 */
public class DurableHandleResponse implements CreateContextResponse {

    /**
     * Context name for durable handle response
     */
    public static final String CONTEXT_NAME = "DHnQ";

    private static final byte[] CONTEXT_NAME_BYTES = CONTEXT_NAME.getBytes();

    // The response structure is reserved and must be zero (8 bytes)
    private byte[] reserved = new byte[8];

    /**
     * Create a new durable handle response
     */
    public DurableHandleResponse() {
        // Reserved field initialized to zeros
    }

    @Override
    public byte[] getName() {
        return CONTEXT_NAME_BYTES;
    }

    @Override
    public int decode(byte[] buffer, int bufferIndex, int len) throws SMBProtocolDecodingException {
        if (len != 8) {
            throw new SMBProtocolDecodingException("Invalid durable handle response length: " + len);
        }

        // Read reserved field (should be all zeros but we don't validate)
        System.arraycopy(buffer, bufferIndex, reserved, 0, 8);
        return 8;
    }

    /**
     * Get the context name as string
     * @return the context name
     */
    public String getContextName() {
        return CONTEXT_NAME;
    }
}
