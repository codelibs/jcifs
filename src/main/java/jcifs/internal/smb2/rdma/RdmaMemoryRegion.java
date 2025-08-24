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
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package jcifs.internal.smb2.rdma;

import java.nio.ByteBuffer;
import java.util.EnumSet;

/**
 * Abstract base class for RDMA memory regions.
 *
 * Represents a registered memory region that can be used for
 * RDMA operations. The memory region contains a buffer, access
 * permissions, and keys for local and remote access.
 */
public abstract class RdmaMemoryRegion implements AutoCloseable {

    /** Memory buffer for RDMA operations */
    protected final ByteBuffer buffer;
    /** Access permissions for this memory region */
    protected final EnumSet<RdmaAccess> accessFlags;
    /** Local key for accessing this memory region */
    protected final int localKey;
    /** Remote key for remote RDMA access */
    protected final int remoteKey;
    /** Virtual address of the memory region */
    protected final long address;
    /** Flag indicating if the memory region is still valid */
    protected volatile boolean valid;

    /**
     * Create new RDMA memory region
     *
     * @param buffer memory buffer to register
     * @param access access permissions
     */
    public RdmaMemoryRegion(ByteBuffer buffer, EnumSet<RdmaAccess> access) {
        this.buffer = buffer;
        this.accessFlags = access;
        this.localKey = generateLocalKey();
        this.remoteKey = generateRemoteKey();
        this.address = getBufferAddress(buffer);
        this.valid = true;
    }

    /**
     * Get the underlying buffer
     *
     * @return memory buffer
     * @throws IllegalStateException if memory region has been invalidated
     */
    public ByteBuffer getBuffer() {
        if (!valid) {
            throw new IllegalStateException("Memory region invalidated");
        }
        return buffer;
    }

    /**
     * Get local memory key
     *
     * @return local key for RDMA operations
     */
    public int getLocalKey() {
        return localKey;
    }

    /**
     * Get remote memory key
     *
     * @return remote key for RDMA operations
     */
    public int getRemoteKey() {
        return remoteKey;
    }

    /**
     * Get memory address
     *
     * @return memory address
     */
    public long getAddress() {
        return address;
    }

    /**
     * Get size of memory region
     *
     * @return size in bytes
     */
    public int getSize() {
        return buffer.limit();
    }

    /**
     * Check if region has specific access permission
     *
     * @param access access permission to check
     * @return true if access is allowed, false otherwise
     */
    public boolean hasAccess(RdmaAccess access) {
        return accessFlags.contains(access);
    }

    /**
     * Check if memory region is still valid
     *
     * @return true if valid, false if invalidated
     */
    public boolean isValid() {
        return valid;
    }

    /**
     * Invalidate this memory region
     *
     * After invalidation, the region cannot be used for RDMA operations.
     */
    public abstract void invalidate();

    /**
     * Generate local key for this memory region
     *
     * @return local key
     */
    protected abstract int generateLocalKey();

    /**
     * Generate remote key for this memory region
     *
     * @return remote key
     */
    protected abstract int generateRemoteKey();

    /**
     * Get native memory address of the buffer
     *
     * @param buffer buffer to get address for
     * @return native memory address
     */
    protected abstract long getBufferAddress(ByteBuffer buffer);

    @Override
    public void close() {
        invalidate();
        valid = false;
    }
}
