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

import jcifs.internal.smb2.create.CreateContextRequest;
import jcifs.internal.util.SMBUtil;

/**
 * SMB2 Durable Handle V2 Request Create Context (DH2Q)
 *
 * MS-SMB2 Section 2.2.13.2.4
 */
public class DurableHandleV2Request implements CreateContextRequest {

    /**
     * Context name for durable handle V2 request
     */
    public static final String CONTEXT_NAME = "DH2Q";

    private static final byte[] CONTEXT_NAME_BYTES = CONTEXT_NAME.getBytes();
    private static final int STRUCTURE_SIZE = 32; // Corrected to 32 bytes as per MS-SMB2

    // MS-SMB2: Timeout is specified in 100-nanosecond intervals, but we store in milliseconds
    private long timeoutMs; // timeout in milliseconds (for application use)
    private int flags;
    private HandleGuid createGuid;

    /**
     * Create a new durable handle V2 request
     * @param timeoutMs the timeout in milliseconds (0 for persistent handles)
     * @param persistent true if this should be a persistent handle
     */
    public DurableHandleV2Request(long timeoutMs, boolean persistent) {
        this.timeoutMs = timeoutMs;
        this.flags = persistent ? Smb2HandleCapabilities.SMB2_DHANDLE_FLAG_PERSISTENT : 0;
        this.createGuid = new HandleGuid();
    }

    /**
     * Create a new durable handle V2 request with specific GUID
     * @param timeoutMs the timeout in milliseconds
     * @param persistent true if this should be a persistent handle
     * @param createGuid the create GUID to use
     */
    public DurableHandleV2Request(long timeoutMs, boolean persistent, HandleGuid createGuid) {
        this.timeoutMs = timeoutMs;
        this.flags = persistent ? Smb2HandleCapabilities.SMB2_DHANDLE_FLAG_PERSISTENT : 0;
        this.createGuid = createGuid;
    }

    @Override
    public byte[] getName() {
        return CONTEXT_NAME_BYTES;
    }

    /**
     * Get the create GUID for this request
     * @return the create GUID
     */
    public HandleGuid getCreateGuid() {
        return createGuid;
    }

    /**
     * Get the timeout value in milliseconds
     * @return the timeout in milliseconds
     */
    public long getTimeoutMs() {
        return timeoutMs;
    }

    /**
     * Get the timeout value in 100-nanosecond intervals as required by MS-SMB2
     * @return the timeout in 100-nanosecond intervals
     */
    public long getTimeoutFor100Ns() {
        if (timeoutMs == 0) {
            return 0L; // Persistent handles use 0
        }
        // Convert milliseconds to 100-nanosecond intervals
        // 1 ms = 10,000 * 100ns intervals
        long intervals = timeoutMs * 10000L;
        // MS-SMB2 timeout field is 4 bytes (uint32), so clamp to max value
        return Math.min(intervals, 0xFFFFFFFFL);
    }

    /**
     * Get the flags
     * @return the flags
     */
    public int getFlags() {
        return flags;
    }

    /**
     * Check if this is a persistent handle request
     * @return true if persistent
     */
    public boolean isPersistent() {
        return (flags & Smb2HandleCapabilities.SMB2_DHANDLE_FLAG_PERSISTENT) != 0;
    }

    @Override
    public int size() {
        // Context header (16) + name length (4) + padding to 8-byte alignment (4) + data (32)
        return 16 + 4 + 4 + STRUCTURE_SIZE;
    }

    @Override
    public int encode(byte[] dst, int dstIndex) {
        int start = dstIndex;

        // Write context header
        SMBUtil.writeInt4(0, dst, dstIndex); // Next (offset to next context, 0 for last)
        dstIndex += 4;

        SMBUtil.writeInt2(16, dst, dstIndex); // NameOffset (from start of context)
        dstIndex += 2;

        SMBUtil.writeInt2(4, dst, dstIndex); // NameLength
        dstIndex += 2;

        SMBUtil.writeInt2(0, dst, dstIndex); // Reserved
        dstIndex += 2;

        SMBUtil.writeInt2(24, dst, dstIndex); // DataOffset (from start of context)
        dstIndex += 2;

        SMBUtil.writeInt4(STRUCTURE_SIZE, dst, dstIndex); // DataLength
        dstIndex += 4;

        // Write context name
        System.arraycopy(CONTEXT_NAME_BYTES, 0, dst, dstIndex, 4);
        dstIndex += 4;

        // Padding to align data to 8-byte boundary
        dstIndex += 4;

        // Write durable handle V2 request data (32 bytes total)
        // MS-SMB2 2.2.13.2.4 structure:
        SMBUtil.writeInt4((int) getTimeoutFor100Ns(), dst, dstIndex); // Timeout (4 bytes in 100-ns intervals)
        dstIndex += 4;

        SMBUtil.writeInt4(flags, dst, dstIndex); // Flags (4 bytes)
        dstIndex += 4;

        SMBUtil.writeInt8(0, dst, dstIndex); // Reserved (8 bytes)
        dstIndex += 8;

        System.arraycopy(createGuid.toBytes(), 0, dst, dstIndex, 16); // CreateGuid (16 bytes)
        dstIndex += 16;

        return dstIndex - start;
    }
}
