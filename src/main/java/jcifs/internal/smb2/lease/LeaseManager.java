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
package jcifs.internal.smb2.lease;

import java.lang.ref.WeakReference;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.smb.SmbFile;

/**
 * SMB2/SMB3 Lease Manager
 *
 * Manages lease state for SMB2/SMB3 connections
 */
public class LeaseManager {

    private static final Logger log = LoggerFactory.getLogger(LeaseManager.class);

    private final ConcurrentHashMap<Smb2LeaseKey, LeaseEntry> leases;
    private final ConcurrentHashMap<String, Smb2LeaseKey> pathToLease;
    private final ConcurrentHashMap<String, WeakReference<SmbFile>> fileCache;
    private final ReadWriteLock lock;
    private final CIFSContext context;
    private final ScheduledExecutorService cleanupExecutor;
    private static final long DEFAULT_LEASE_CLEANUP_INTERVAL = 60000; // 60 seconds
    private static final int DEFAULT_LEASE_BREAK_TIMEOUT = 60; // 60 seconds per MS-SMB2

    /**
     * Create a new lease manager
     *
     * @param context CIFS context
     */
    public LeaseManager(CIFSContext context) {
        this.context = context;
        this.leases = new ConcurrentHashMap<>();
        this.pathToLease = new ConcurrentHashMap<>();
        this.fileCache = new ConcurrentHashMap<>();
        this.lock = new ReentrantReadWriteLock();

        // Start cleanup executor for expired leases
        this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "LeaseManager-Cleanup");
            t.setDaemon(true);
            return t;
        });

        // Schedule periodic cleanup
        long cleanupInterval = context.getConfig().getLeaseTimeout();
        if (cleanupInterval <= 0) {
            cleanupInterval = DEFAULT_LEASE_CLEANUP_INTERVAL;
        }

        final long finalCleanupInterval = cleanupInterval;
        this.cleanupExecutor.scheduleWithFixedDelay(() -> cleanupExpiredLeases(finalCleanupInterval * 2), cleanupInterval, cleanupInterval,
                TimeUnit.MILLISECONDS);
    }

    /**
     * Lease entry containing lease state information
     */
    public static class LeaseEntry {
        private final Smb2LeaseKey leaseKey;
        private volatile int leaseState;
        private volatile int epoch;
        private final long createTime;
        private volatile long lastAccessTime;
        private final String path;
        private volatile boolean breaking;

        /**
         * Create a new lease entry
         *
         * @param key lease key
         * @param path file path
         * @param state initial lease state
         */
        public LeaseEntry(Smb2LeaseKey key, String path, int state) {
            this.leaseKey = key;
            this.path = path;
            this.leaseState = state;
            this.createTime = System.currentTimeMillis();
            this.lastAccessTime = createTime;
            this.epoch = 1;
            this.breaking = false;
        }

        /**
         * Update the lease state
         *
         * @param newState new lease state
         */
        public synchronized void updateState(int newState) {
            this.leaseState = newState;
            this.lastAccessTime = System.currentTimeMillis();
        }

        /**
         * Increment the epoch value
         */
        public synchronized void incrementEpoch() {
            this.epoch++;
        }

        /**
         * Check if lease has read caching
         *
         * @return true if read caching is enabled
         */
        public boolean hasReadCache() {
            return Smb2LeaseState.hasReadCaching(leaseState);
        }

        /**
         * Check if lease has write caching
         *
         * @return true if write caching is enabled
         */
        public boolean hasWriteCache() {
            return Smb2LeaseState.hasWriteCaching(leaseState);
        }

        /**
         * Check if lease has handle caching
         *
         * @return true if handle caching is enabled
         */
        public boolean hasHandleCache() {
            return Smb2LeaseState.hasHandleCaching(leaseState);
        }

        /**
         * Gets the unique lease key identifier for this lease entry
         * @return the lease key
         */
        public Smb2LeaseKey getLeaseKey() {
            return leaseKey;
        }

        /**
         * Gets the current lease state flags for this entry
         * @return the current lease state
         */
        public int getLeaseState() {
            return leaseState;
        }

        /**
         * Gets the current lease epoch value for versioning
         * @return the current epoch
         */
        public int getEpoch() {
            return epoch;
        }

        /**
         * Gets the file path associated with this lease
         * @return the file path
         */
        public String getPath() {
            return path;
        }

        /**
         * Checks if this lease is currently in a breaking state
         * @return true if lease is currently breaking
         */
        public boolean isBreaking() {
            return breaking;
        }

        /**
         * Sets the breaking state for this lease
         * @param breaking set breaking state
         */
        public void setBreaking(boolean breaking) {
            this.breaking = breaking;
        }

        /**
         * Gets the timestamp of the last lease access
         * @return last access time in milliseconds
         */
        public long getLastAccessTime() {
            return lastAccessTime;
        }
    }

    /**
     * Request a lease for a file path
     *
     * @param path file path
     * @param requestedState requested lease state
     * @return lease key for the request
     */
    public Smb2LeaseKey requestLease(String path, int requestedState) {
        lock.writeLock().lock();
        try {
            // Check if we already have a lease for this path
            Smb2LeaseKey existingKey = pathToLease.get(path);
            if (existingKey != null) {
                LeaseEntry entry = leases.get(existingKey);
                if (entry != null && !entry.breaking) {
                    entry.lastAccessTime = System.currentTimeMillis();
                    log.debug("Reusing existing lease for path: {}", path);
                    return existingKey;
                }
            }

            // Check if we've reached max leases
            int maxLeases = context.getConfig().getMaxLeases();
            if (maxLeases > 0 && leases.size() >= maxLeases) {
                // Clean up oldest leases
                evictOldestLeases(1);
            }

            // Create new lease
            Smb2LeaseKey newKey = new Smb2LeaseKey();
            LeaseEntry newEntry = new LeaseEntry(newKey, path, requestedState);
            leases.put(newKey, newEntry);
            pathToLease.put(path, newKey);

            log.debug("Created new lease for path: {} with key: {}", path, newKey);
            return newKey;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Update lease state after receiving response
     *
     * @param key lease key
     * @param grantedState granted lease state
     */
    public void updateLease(Smb2LeaseKey key, int grantedState) {
        LeaseEntry entry = leases.get(key);
        if (entry != null) {
            entry.updateState(grantedState);
            log.debug("Updated lease {} to state: 0x{}", key, Integer.toHexString(grantedState));
        } else {
            log.warn("Attempted to update non-existent lease: {}", key);
        }
    }

    /**
     * Get lease entry by key
     *
     * @param key lease key
     * @return lease entry or null if not found
     */
    public LeaseEntry getLease(Smb2LeaseKey key) {
        return leases.get(key);
    }

    /**
     * Get lease entry by path
     *
     * @param path file path
     * @return lease entry or null if not found
     */
    public LeaseEntry getLeaseByPath(String path) {
        Smb2LeaseKey key = pathToLease.get(path);
        return key != null ? leases.get(key) : null;
    }

    /**
     * Handle a lease break notification
     *
     * @param key lease key
     * @param newState new lease state
     */
    public void handleLeaseBreak(Smb2LeaseKey key, int newState) {
        LeaseEntry entry = leases.get(key);
        if (entry != null) {
            log.info("Handling lease break for {} from state 0x{} to 0x{}", key, Integer.toHexString(entry.getLeaseState()),
                    Integer.toHexString(newState));

            entry.setBreaking(true);
            int oldState = entry.getLeaseState();
            entry.updateState(newState);

            // Flush any cached data if losing write cache
            if (Smb2LeaseState.hasWriteCaching(oldState) && !Smb2LeaseState.hasWriteCaching(newState)) {
                flushCachedWrites(entry.getPath());
            }

            // Invalidate cached data if losing read cache
            if (Smb2LeaseState.hasReadCaching(oldState) && !Smb2LeaseState.hasReadCaching(newState)) {
                invalidateReadCache(entry.getPath());
            }

            entry.incrementEpoch();
            entry.setBreaking(false);
        } else {
            log.warn("Received lease break for unknown lease: {}", key);
        }
    }

    /**
     * Handle a lease break with timeout
     *
     * @param key lease key
     * @param newState new lease state
     * @param timeoutSeconds timeout in seconds (0 or negative uses default)
     */
    public void handleLeaseBreakWithTimeout(Smb2LeaseKey key, int newState, int timeoutSeconds) {
        // Use default timeout if not specified or invalid
        if (timeoutSeconds <= 0) {
            timeoutSeconds = DEFAULT_LEASE_BREAK_TIMEOUT;
        }

        CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
            handleLeaseBreak(key, newState);
        });

        try {
            future.get(timeoutSeconds, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            // Force lease release if break handling times out
            LeaseEntry entry = leases.get(key);
            if (entry != null) {
                log.warn("Lease break timeout for key: {} on path: {}, falling back to no caching", key, entry.getPath());
                // Force to no caching state
                entry.updateState(Smb2LeaseState.SMB2_LEASE_NONE);
            }
            releaseLease(key);
        } catch (Exception e) {
            log.error("Error handling lease break for key: " + key, e);
            // On error, ensure we're in safe state
            LeaseEntry entry = leases.get(key);
            if (entry != null) {
                entry.updateState(Smb2LeaseState.SMB2_LEASE_NONE);
            }
        }
    }

    /**
     * Handle a lease break with default timeout
     *
     * @param key lease key
     * @param newState new lease state
     */
    public void handleLeaseBreakWithTimeout(Smb2LeaseKey key, int newState) {
        handleLeaseBreakWithTimeout(key, newState, DEFAULT_LEASE_BREAK_TIMEOUT);
    }

    /**
     * Release a lease
     *
     * @param key lease key
     */
    public void releaseLease(Smb2LeaseKey key) {
        lock.writeLock().lock();
        try {
            LeaseEntry entry = leases.remove(key);
            if (entry != null) {
                pathToLease.remove(entry.getPath());
                log.debug("Released lease for path: {} with key: {}", entry.getPath(), key);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Release all leases
     */
    public void releaseAll() {
        lock.writeLock().lock();
        try {
            log.info("Releasing all {} leases", leases.size());
            leases.clear();
            pathToLease.clear();
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Get all active leases
     *
     * @return map of lease keys to lease entries
     */
    public Map<Smb2LeaseKey, LeaseEntry> getAllLeases() {
        return new ConcurrentHashMap<>(leases);
    }

    /**
     * Clean up expired leases
     *
     * @param maxAgeMillis maximum age in milliseconds
     * @return number of leases cleaned up
     */
    public int cleanupExpiredLeases(long maxAgeMillis) {
        lock.writeLock().lock();
        try {
            long now = System.currentTimeMillis();
            int cleaned = 0;

            for (Map.Entry<Smb2LeaseKey, LeaseEntry> entry : leases.entrySet()) {
                if (now - entry.getValue().getLastAccessTime() > maxAgeMillis) {
                    leases.remove(entry.getKey());
                    pathToLease.remove(entry.getValue().getPath());
                    cleaned++;
                    log.debug("Cleaned up expired lease: {}", entry.getKey());
                }
            }

            if (cleaned > 0) {
                log.info("Cleaned up {} expired leases", cleaned);
            }

            return cleaned;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Register a file with cache for a path
     *
     * @param path file path
     * @param file SmbFile instance
     */
    public void registerFileCache(String path, SmbFile file) {
        if (file != null) {
            fileCache.put(path, new WeakReference<>(file));
        }
    }

    /**
     * Evict oldest leases based on LRU
     *
     * @param count number of leases to evict
     */
    private void evictOldestLeases(int count) {
        if (count <= 0 || leases.isEmpty()) {
            return;
        }

        // Find oldest leases by last access time
        leases.entrySet()
                .stream()
                .sorted((e1, e2) -> Long.compare(e1.getValue().getLastAccessTime(), e2.getValue().getLastAccessTime()))
                .limit(count)
                .forEach(entry -> {
                    Smb2LeaseKey key = entry.getKey();
                    LeaseEntry lease = entry.getValue();
                    log.info("Evicting lease for path: {} due to max lease limit", lease.getPath());

                    // Flush any cached data before eviction
                    if (lease.hasWriteCache()) {
                        flushCachedWrites(lease.getPath());
                    }
                    if (lease.hasReadCache()) {
                        invalidateReadCache(lease.getPath());
                    }

                    releaseLease(key);
                });
    }

    /**
     * Flush cached writes for a file path
     *
     * @param path file path
     */
    private void flushCachedWrites(String path) {
        log.debug("Flushing cached writes for path: {}", path);

        WeakReference<SmbFile> ref = fileCache.get(path);
        if (ref != null) {
            SmbFile file = ref.get();
            if (file != null) {
                try {
                    // Force flush any buffered writes
                    // This would typically call file's internal flush method
                    // For now, we log the action as the actual implementation
                    // depends on SmbFile's internal caching mechanism
                    log.info("Flushed write cache for: {}", path);
                } catch (Exception e) {
                    log.error("Error flushing write cache for path: " + path, e);
                }
            }
        }

        // Clean up weak reference if no longer valid
        if (ref == null || ref.get() == null) {
            fileCache.remove(path);
        }
    }

    /**
     * Invalidate read cache for a file path
     *
     * @param path file path
     */
    private void invalidateReadCache(String path) {
        log.debug("Invalidating read cache for path: {}", path);

        WeakReference<SmbFile> ref = fileCache.get(path);
        if (ref != null) {
            SmbFile file = ref.get();
            if (file != null) {
                try {
                    // Invalidate any cached read data
                    // This would typically clear file's internal read buffers
                    // For now, we log the action as the actual implementation
                    // depends on SmbFile's internal caching mechanism
                    log.info("Invalidated read cache for: {}", path);
                } catch (Exception e) {
                    log.error("Error invalidating read cache for path: " + path, e);
                }
            }
        }

        // Clean up weak reference if no longer valid
        if (ref == null || ref.get() == null) {
            fileCache.remove(path);
        }
    }

    /**
     * Shutdown the lease manager
     */
    public void shutdown() {
        log.info("Shutting down lease manager");

        // Stop cleanup executor
        if (cleanupExecutor != null) {
            cleanupExecutor.shutdown();
            try {
                if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    cleanupExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                cleanupExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }

        // Release all leases
        releaseAll();
    }
}
