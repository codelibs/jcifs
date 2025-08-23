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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.EnumSet;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * RDMA buffer manager for efficient memory region pooling.
 *
 * Manages pools of pre-registered memory regions to avoid the overhead
 * of frequent registration/deregistration during RDMA operations.
 */
public class RdmaBufferManager implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(RdmaBufferManager.class);

    private final RdmaProvider provider;
    private final ConcurrentLinkedQueue<RdmaMemoryRegion> availableSendRegions;
    private final ConcurrentLinkedQueue<RdmaMemoryRegion> availableReceiveRegions;
    private final AtomicLong totalAllocated;
    private final AtomicLong totalReleased;

    // Buffer pool configuration
    private final int initialSendBuffers = 32;
    private final int initialReceiveBuffers = 64;
    private final int sendBufferSize = 65536; // 64KB
    private final int receiveBufferSize = 65536; // 64KB

    /**
     * Create new RDMA buffer manager
     *
     * @param provider RDMA provider for memory registration
     */
    public RdmaBufferManager(RdmaProvider provider) {
        this.provider = provider;
        this.availableSendRegions = new ConcurrentLinkedQueue<>();
        this.availableReceiveRegions = new ConcurrentLinkedQueue<>();
        this.totalAllocated = new AtomicLong();
        this.totalReleased = new AtomicLong();

        // Pre-allocate buffer pool
        initializeBufferPool();
    }

    /**
     * Initialize the buffer pool with pre-allocated regions
     */
    private void initializeBufferPool() {
        // Allocate send buffers
        for (int i = 0; i < initialSendBuffers; i++) {
            try {
                ByteBuffer buffer = ByteBuffer.allocateDirect(sendBufferSize);
                RdmaMemoryRegion region = provider.registerMemory(buffer, EnumSet.of(RdmaAccess.LOCAL_READ, RdmaAccess.REMOTE_READ));
                availableSendRegions.offer(region);
                totalAllocated.incrementAndGet();
            } catch (IOException e) {
                log.warn("Failed to pre-allocate send buffer", e);
            }
        }

        // Allocate receive buffers
        for (int i = 0; i < initialReceiveBuffers; i++) {
            try {
                ByteBuffer buffer = ByteBuffer.allocateDirect(receiveBufferSize);
                RdmaMemoryRegion region = provider.registerMemory(buffer, EnumSet.of(RdmaAccess.LOCAL_WRITE, RdmaAccess.REMOTE_WRITE));
                availableReceiveRegions.offer(region);
                totalAllocated.incrementAndGet();
            } catch (IOException e) {
                log.warn("Failed to pre-allocate receive buffer", e);
            }
        }

        log.info("Initialized RDMA buffer pool with {} send and {} receive buffers", availableSendRegions.size(),
                availableReceiveRegions.size());
    }

    /**
     * Get a send region from the pool or allocate a new one
     *
     * @param minSize minimum required size
     * @return memory region for sending
     * @throws IOException if allocation fails
     */
    public RdmaMemoryRegion getSendRegion(int minSize) throws IOException {
        if (minSize <= sendBufferSize) {
            RdmaMemoryRegion region = availableSendRegions.poll();
            if (region != null) {
                region.getBuffer().clear();
                return region;
            }
        }

        // Allocate new buffer
        ByteBuffer buffer = ByteBuffer.allocateDirect(Math.max(minSize, sendBufferSize));
        RdmaMemoryRegion region = provider.registerMemory(buffer, EnumSet.of(RdmaAccess.LOCAL_READ, RdmaAccess.REMOTE_READ));
        totalAllocated.incrementAndGet();
        return region;
    }

    /**
     * Release a send region back to the pool
     *
     * @param region memory region to release
     */
    public void releaseSendRegion(RdmaMemoryRegion region) {
        if (region.getSize() == sendBufferSize && availableSendRegions.size() < initialSendBuffers * 2) {
            availableSendRegions.offer(region);
        } else {
            region.close();
            totalReleased.incrementAndGet();
        }
    }

    /**
     * Get a receive region from the pool or allocate a new one
     *
     * @return memory region for receiving
     * @throws IOException if allocation fails
     */
    public RdmaMemoryRegion getReceiveRegion() throws IOException {
        RdmaMemoryRegion region = availableReceiveRegions.poll();
        if (region != null) {
            region.getBuffer().clear();
            return region;
        }

        // Allocate new buffer
        ByteBuffer buffer = ByteBuffer.allocateDirect(receiveBufferSize);
        RdmaMemoryRegion newRegion = provider.registerMemory(buffer, EnumSet.of(RdmaAccess.LOCAL_WRITE, RdmaAccess.REMOTE_WRITE));
        totalAllocated.incrementAndGet();
        return newRegion;
    }

    /**
     * Release a receive region back to the pool
     *
     * @param region memory region to release
     */
    public void releaseReceiveRegion(RdmaMemoryRegion region) {
        if (availableReceiveRegions.size() < initialReceiveBuffers * 2) {
            availableReceiveRegions.offer(region);
        } else {
            region.close();
            totalReleased.incrementAndGet();
        }
    }

    /**
     * Allocate a direct buffer for temporary use
     *
     * @param size buffer size in bytes
     * @return direct byte buffer
     */
    public ByteBuffer allocateBuffer(int size) {
        return ByteBuffer.allocateDirect(size);
    }

    /**
     * Release a temporary buffer
     *
     * For direct buffers, we rely on GC. A more sophisticated
     * implementation could maintain a buffer pool here as well.
     *
     * @param buffer buffer to release
     */
    public void releaseBuffer(ByteBuffer buffer) {
        // For direct buffers, we rely on GC
        // Could implement a more sophisticated buffer pool here
    }

    /**
     * Clean up all pooled regions
     *
     * This method should be called when shutting down to
     * release all resources.
     */
    public void cleanup() {
        // Clean up all pooled regions
        RdmaMemoryRegion region;

        while ((region = availableSendRegions.poll()) != null) {
            region.close();
            totalReleased.incrementAndGet();
        }

        while ((region = availableReceiveRegions.poll()) != null) {
            region.close();
            totalReleased.incrementAndGet();
        }

        log.info("RDMA buffer manager cleanup complete. Total allocated: {}, released: {}", totalAllocated.get(), totalReleased.get());
    }

    /**
     * Close the buffer manager and release all resources
     *
     * @throws Exception if cleanup fails
     */
    @Override
    public void close() throws Exception {
        cleanup();
    }

    /**
     * Get total number of regions allocated
     *
     * @return total allocated regions
     */
    public long getTotalAllocated() {
        return totalAllocated.get();
    }

    /**
     * Get total number of regions released
     *
     * @return total released regions
     */
    public long getTotalReleased() {
        return totalReleased.get();
    }

    /**
     * Get number of currently active regions
     *
     * @return active regions (allocated - released)
     */
    public long getActiveRegions() {
        return totalAllocated.get() - totalReleased.get();
    }

    /**
     * Get number of available send regions in pool
     *
     * @return available send regions
     */
    public int getAvailableSendRegions() {
        return availableSendRegions.size();
    }

    /**
     * Get number of available receive regions in pool
     *
     * @return available receive regions
     */
    public int getAvailableReceiveRegions() {
        return availableReceiveRegions.size();
    }
}
