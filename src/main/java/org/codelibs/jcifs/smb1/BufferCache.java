/* org.codelibs.jcifs.smb smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
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

package org.codelibs.jcifs.smb1;

/**
 * Buffer cache implementation for SMB1 protocol operations.
 * Manages a pool of byte buffers to reduce garbage collection overhead.
 *
 * Performance optimizations:
 * - Uses ConcurrentLinkedQueue for O(1) operations
 * - Lock-free operations for better concurrency
 * - Proper buffer validation and limits
 */
public class BufferCache {

    /**
     * Private constructor to prevent instantiation of this utility class.
     */
    private BufferCache() {
        // Utility class - not instantiable
    }

    private static final int MAX_BUFFERS = Config.getInt("jcifs.maxBuffers", 16);
    private static final int MAX_BUFFER_SIZE = 0x100000; // 1MB maximum

    // Use concurrent queue for lock-free operations
    private static final java.util.concurrent.ConcurrentLinkedQueue<byte[]> bufferQueue =
            new java.util.concurrent.ConcurrentLinkedQueue<>();

    // Track queue size with atomic counter for efficiency
    private static final java.util.concurrent.atomic.AtomicInteger queueSize = new java.util.concurrent.atomic.AtomicInteger(0);

    /**
     * Gets a buffer from the cache or creates a new one if the cache is empty.
     *
     * Performance: O(1) operation using concurrent queue
     *
     * @return a byte buffer for SMB operations
     * @throws IllegalStateException if buffer size exceeds maximum allowed
     */
    static public byte[] getBuffer() {
        // Try to get from cache first - O(1) operation
        byte[] buf = bufferQueue.poll();
        if (buf != null) {
            queueSize.decrementAndGet();
            return buf;
        }

        // Validate buffer size to prevent overflow
        int bufferSize = SmbComTransaction.TRANSACTION_BUF_SIZE;
        if (bufferSize < 0 || bufferSize > MAX_BUFFER_SIZE) {
            throw new IllegalStateException("Invalid buffer size: " + bufferSize);
        }

        return new byte[bufferSize];
    }

    static void getBuffers(final SmbComTransaction req, final SmbComTransactionResponse rsp) {
        req.txn_buf = getBuffer();
        rsp.txn_buf = getBuffer();
    }

    /**
     * Returns a buffer to the cache for reuse.
     *
     * Performance: O(1) operation with size limit check
     *
     * @param buf the buffer to return to the cache
     */
    static public void releaseBuffer(final byte[] buf) {
        // Validate buffer before returning to cache
        if (buf == null || buf.length != SmbComTransaction.TRANSACTION_BUF_SIZE) {
            return; // Silently ignore invalid buffers
        }

        // Only cache if we haven't reached the limit - O(1) check
        if (queueSize.get() < MAX_BUFFERS) {
            if (bufferQueue.offer(buf)) { // O(1) operation
                queueSize.incrementAndGet();
            }
        }
        // If queue is full, let the buffer be garbage collected
    }

    /**
     * Get current cache statistics for monitoring
     * @return formatted statistics string
     */
    public static String getCacheStatistics() {
        return String.format("BufferCache: queued=%d, max=%d, utilization=%.1f%%", queueSize.get(), MAX_BUFFERS,
                (queueSize.get() * 100.0 / MAX_BUFFERS));
    }

    /**
     * Clear all cached buffers (for testing or cleanup)
     */
    public static void clearCache() {
        bufferQueue.clear();
        queueSize.set(0);
    }
}
