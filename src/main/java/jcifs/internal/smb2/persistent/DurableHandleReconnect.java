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

import java.util.Arrays;

import jcifs.internal.smb2.create.CreateContextRequest;
import jcifs.internal.util.SMBUtil;

/**
 * SMB2 Durable Handle Reconnect Create Context (DHnC)
 *
 * MS-SMB2 Section 2.2.13.2.5
 */
public class DurableHandleReconnect implements CreateContextRequest {

    /**
     * Context name for durable handle reconnect
     */
    public static final String CONTEXT_NAME = "DHnC";

    private static final byte[] CONTEXT_NAME_BYTES = CONTEXT_NAME.getBytes();
    private static final int STRUCTURE_SIZE = 16;

    private byte[] fileId; // 16-byte file ID from previous open

    /**
     * Create a new durable handle reconnect context
     * @param fileId the 16-byte file ID from the previous open
     */
    public DurableHandleReconnect(byte[] fileId) {
        if (fileId.length != 16) {
            throw new IllegalArgumentException("File ID must be 16 bytes");
        }
        this.fileId = Arrays.copyOf(fileId, 16);
    }

    @Override
    public byte[] getName() {
        return CONTEXT_NAME_BYTES;
    }

    /**
     * Get the file ID
     * @return the 16-byte file ID
     */
    public byte[] getFileId() {
        return Arrays.copyOf(fileId, 16);
    }

    @Override
    public int size() {
        // Context header (16) + name length (4) + padding to 8-byte alignment + data (16)
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

        // Write file ID (16 bytes)
        System.arraycopy(fileId, 0, dst, dstIndex, 16);
        dstIndex += 16;

        return dstIndex - start;
    }
}
