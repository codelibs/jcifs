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

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.UUID;

/**
 * Handle GUID structure for SMB2/3 durable and persistent handles.
 * Provides a unique identifier for each handle that can be used
 * for reconnection after network failures or server reboots.
 *
 * According to MS-SMB2, the GUID is a 16-byte structure with little-endian
 * byte ordering for the individual components.
 */
public class HandleGuid implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * The underlying UUID representing this handle GUID
     */
    private final UUID guid;

    /**
     * Create a new random handle GUID
     */
    public HandleGuid() {
        this.guid = UUID.randomUUID();
    }

    /**
     * Create a handle GUID from existing bytes
     * @param bytes the 16-byte GUID data in little-endian format (SMB wire format)
     */
    public HandleGuid(byte[] bytes) {
        if (bytes.length != 16) {
            throw new IllegalArgumentException("GUID must be 16 bytes");
        }

        // MS-SMB2 specifies little-endian byte ordering for GUID components
        // Convert from little-endian wire format to Java UUID
        ByteBuffer bb = ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN);

        // Read GUID components in little-endian order
        int data1 = bb.getInt(); // first 4 bytes (little-endian)
        short data2 = bb.getShort(); // next 2 bytes (little-endian)
        short data3 = bb.getShort(); // next 2 bytes (little-endian)

        // The last 8 bytes are read as big-endian (network byte order for the high/low parts)
        ByteBuffer bb2 = ByteBuffer.wrap(bytes, 8, 8).order(java.nio.ByteOrder.BIG_ENDIAN);
        long data4 = bb2.getLong();

        // Construct UUID from components - Java UUID expects big-endian representation
        long mostSig = ((long) data1 << 32) | ((long) (data2 & 0xFFFF) << 16) | (data3 & 0xFFFF);
        long leastSig = data4;

        this.guid = new UUID(mostSig, leastSig);
    }

    /**
     * Create a handle GUID from existing UUID
     * @param uuid the UUID to wrap
     */
    public HandleGuid(UUID uuid) {
        this.guid = uuid;
    }

    /**
     * Convert the GUID to byte array for wire format (little-endian as per MS-SMB2)
     * @return 16-byte array representing the GUID in SMB wire format
     */
    public byte[] toBytes() {
        byte[] result = new byte[16];
        ByteBuffer bb = ByteBuffer.wrap(result).order(java.nio.ByteOrder.LITTLE_ENDIAN);

        long mostSig = guid.getMostSignificantBits();
        long leastSig = guid.getLeastSignificantBits();

        // Extract GUID components from UUID
        int data1 = (int) (mostSig >>> 32); // first 4 bytes
        short data2 = (short) (mostSig >>> 16); // next 2 bytes
        short data3 = (short) mostSig; // next 2 bytes

        // Write in little-endian format as specified by MS-SMB2
        bb.putInt(data1); // data1 (4 bytes, little-endian)
        bb.putShort(data2); // data2 (2 bytes, little-endian)
        bb.putShort(data3); // data3 (2 bytes, little-endian)

        // Last 8 bytes (data4) written directly as big-endian bytes
        // Extract individual bytes from leastSig and write them directly
        for (int i = 0; i < 8; i++) {
            result[8 + i] = (byte) (leastSig >>> (56 - i * 8));
        }

        return result;
    }

    /**
     * Get the underlying UUID
     * @return the UUID
     */
    public UUID getUuid() {
        return guid;
    }

    @Override
    public String toString() {
        return guid.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null || getClass() != obj.getClass())
            return false;
        HandleGuid that = (HandleGuid) obj;
        return guid.equals(that.guid);
    }

    @Override
    public int hashCode() {
        return guid.hashCode();
    }
}
