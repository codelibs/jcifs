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

import java.util.UUID;
import java.nio.ByteBuffer;
import java.io.Serializable;

/**
 * Handle GUID structure for SMB2/3 durable and persistent handles.
 * Provides a unique identifier for each handle that can be used
 * for reconnection after network failures or server reboots.
 */
public class HandleGuid implements Serializable {

    private static final long serialVersionUID = 1L;

    private final UUID guid;

    /**
     * Create a new random handle GUID
     */
    public HandleGuid() {
        this.guid = UUID.randomUUID();
    }

    /**
     * Create a handle GUID from existing bytes
     * @param bytes the 16-byte GUID data
     */
    public HandleGuid(byte[] bytes) {
        if (bytes.length != 16) {
            throw new IllegalArgumentException("GUID must be 16 bytes");
        }
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        long mostSig = bb.getLong();
        long leastSig = bb.getLong();
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
     * Convert the GUID to byte array for wire format
     * @return 16-byte array representing the GUID
     */
    public byte[] toBytes() {
        ByteBuffer bb = ByteBuffer.allocate(16);
        bb.putLong(guid.getMostSignificantBits());
        bb.putLong(guid.getLeastSignificantBits());
        return bb.array();
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
