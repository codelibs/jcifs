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
 * SMB2 Durable Handle Request Create Context (DHnQ)
 *
 * MS-SMB2 Section 2.2.13.2.3
 *
 * @author jcifs team
 */
public class DurableHandleRequest implements CreateContextRequest {

    /**
     * Context name for durable handle request
     */
    public static final String CONTEXT_NAME = "DHnQ";

    private static final byte[] CONTEXT_NAME_BYTES = CONTEXT_NAME.getBytes();
    private static final int STRUCTURE_SIZE = 16;

    private long reserved; // Must be zero

    /**
     * Create a new durable handle request
     */
    public DurableHandleRequest() {
        this.reserved = 0;
    }

    @Override
    public byte[] getName() {
        return CONTEXT_NAME_BYTES;
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

        // Write durable handle request data (16 bytes of reserved)
        for (int i = 0; i < 16; i++) {
            dst[dstIndex + i] = 0;
        }
        dstIndex += 16;

        return dstIndex - start;
    }
}
