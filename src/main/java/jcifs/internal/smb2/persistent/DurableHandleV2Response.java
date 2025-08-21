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
import jcifs.internal.util.SMBUtil;

/**
 * SMB2 Durable Handle V2 Response Create Context
 *
 * MS-SMB2 Section 2.2.14.2.4
 */
public class DurableHandleV2Response implements CreateContextResponse {

    /**
     * Context name for durable handle V2 response
     */
    public static final String CONTEXT_NAME = "DH2Q";

    private static final byte[] CONTEXT_NAME_BYTES = CONTEXT_NAME.getBytes();

    private long timeout100Ns; // timeout in 100-nanosecond intervals (wire format, unsigned 32-bit)
    private int flags;

    /**
     * Create a new durable handle V2 response
     */
    public DurableHandleV2Response() {
        // Will be populated during decode
    }

    @Override
    public byte[] getName() {
        return CONTEXT_NAME_BYTES;
    }

    @Override
    public int decode(byte[] buffer, int bufferIndex, int len) throws SMBProtocolDecodingException {
        if (len != 8) {
            throw new SMBProtocolDecodingException("Invalid durable handle V2 response length: " + len);
        }

        this.timeout100Ns = SMBUtil.readInt4(buffer, bufferIndex) & 0xFFFFFFFFL; // Timeout (4 bytes, 100-ns intervals, unsigned)
        this.flags = SMBUtil.readInt4(buffer, bufferIndex + 4); // Flags (4 bytes)
        return 8;
    }

    /**
     * Get the timeout value in 100-nanosecond intervals (raw wire format)
     * @return the timeout in 100-nanosecond intervals
     */
    public long getTimeout100Ns() {
        return timeout100Ns;
    }

    /**
     * Get the timeout value converted to milliseconds
     * @return the timeout in milliseconds
     */
    public long getTimeoutMs() {
        if (timeout100Ns == 0) {
            return 0; // Persistent handles
        }
        // Convert from 100-nanosecond intervals to milliseconds
        // 1 ms = 10,000 * 100ns intervals
        return timeout100Ns / 10000L;
    }

    /**
     * Get the flags
     * @return the flags
     */
    public int getFlags() {
        return flags;
    }

    /**
     * Check if this is a persistent handle
     * @return true if persistent
     */
    public boolean isPersistent() {
        return (flags & Smb2HandleCapabilities.SMB2_DHANDLE_FLAG_PERSISTENT) != 0;
    }

    /**
     * Get the context name as string
     * @return the context name
     */
    public String getContextName() {
        return CONTEXT_NAME;
    }
}
