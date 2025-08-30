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
package jcifs.util;

import java.lang.ref.PhantomReference;
import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Centralized resource management for preventing resource leaks.
 * Tracks all AutoCloseable resources and ensures proper cleanup.
 *
 * Features:
 * - Automatic resource cleanup with weak references
 * - Resource leak detection
 * - Resource usage monitoring
 * - Periodic cleanup of abandoned resources
 * - Detailed resource tracking and reporting
 */
public class ResourceManager {

    private static final Logger log = LoggerFactory.getLogger(ResourceManager.class);
    private static final ResourceManager INSTANCE = new ResourceManager();

    private final Map<String, ResourceHolder> activeResources = new ConcurrentHashMap<>();
    private final ReferenceQueue<AutoCloseable> referenceQueue = new ReferenceQueue<>();
    private final AtomicLong resourceIdCounter = new AtomicLong();
    private final AtomicLong totalAllocated = new AtomicLong();
    private final AtomicLong totalReleased = new AtomicLong();
    private final AtomicLong totalLeaks = new AtomicLong();

    private final ScheduledExecutorService cleanupExecutor;
    private ScheduledFuture<?> cleanupTask;
    private volatile boolean shutdownInProgress = false;

    // Configuration
    private long maxResourceAge = TimeUnit.HOURS.toMillis(1); // 1 hour default
    private long cleanupInterval = TimeUnit.MINUTES.toMillis(5); // 5 minutes default
    private boolean leakDetectionEnabled = true;
    private boolean autoCleanupEnabled = true;

    /**
     * Resource holder that tracks resource lifecycle
     */
    private static class ResourceHolder {
        final String resourceId;
        final String resourceType;
        final WeakReference<AutoCloseable> resourceRef;
        final PhantomReference<AutoCloseable> phantomRef;
        final long creationTime;
        final StackTraceElement[] allocationStackTrace;
        volatile boolean closed;

        ResourceHolder(String resourceId, AutoCloseable resource, ReferenceQueue<AutoCloseable> queue) {
            this.resourceId = resourceId;
            this.resourceType = resource.getClass().getSimpleName();
            this.resourceRef = new WeakReference<>(resource);
            this.phantomRef = new PhantomReference<>(resource, queue);
            this.creationTime = System.currentTimeMillis();
            this.allocationStackTrace = Thread.currentThread().getStackTrace();
            this.closed = false;
        }

        boolean isAlive() {
            return resourceRef.get() != null && !closed;
        }

        long getAge() {
            return System.currentTimeMillis() - creationTime;
        }
    }

    private ResourceManager() {
        ThreadFactory threadFactory = r -> {
            Thread t = new Thread(r, "ResourceManager-Cleanup");
            t.setDaemon(true);
            return t;
        };
        cleanupExecutor = Executors.newSingleThreadScheduledExecutor(threadFactory);

        // Add shutdown hook for cleanup
        Runtime.getRuntime().addShutdownHook(new Thread(this::shutdown, "ResourceManager-Shutdown"));

        startCleanupTask();
    }

    /**
     * Get the singleton instance
     *
     * @return ResourceManager instance
     */
    public static ResourceManager getInstance() {
        return INSTANCE;
    }

    /**
     * Register a resource for tracking
     *
     * @param resource the resource to track
     * @return resource ID for tracking
     */
    public String registerResource(AutoCloseable resource) {
        if (resource == null) {
            throw new IllegalArgumentException("Resource cannot be null");
        }

        String resourceId = generateResourceId(resource);
        ResourceHolder holder = new ResourceHolder(resourceId, resource, referenceQueue);

        activeResources.put(resourceId, holder);
        totalAllocated.incrementAndGet();

        log.trace("Registered resource: {} ({})", resourceId, resource.getClass().getSimpleName());

        return resourceId;
    }

    /**
     * Mark a resource as closed
     *
     * @param resourceId the resource ID
     */
    public void markClosed(String resourceId) {
        ResourceHolder holder = activeResources.get(resourceId);
        if (holder != null) {
            holder.closed = true;
            totalReleased.incrementAndGet();
            log.trace("Resource closed: {} ({})", resourceId, holder.resourceType);
        }
    }

    /**
     * Unregister a resource
     *
     * @param resourceId the resource ID
     */
    public void unregisterResource(String resourceId) {
        ResourceHolder holder = activeResources.remove(resourceId);
        if (holder != null) {
            if (!holder.closed) {
                holder.closed = true;
                totalReleased.incrementAndGet();
            }
            log.trace("Unregistered resource: {} ({})", resourceId, holder.resourceType);
        }
    }

    /**
     * Check for and report resource leaks
     */
    public void checkForLeaks() {
        if (!leakDetectionEnabled) {
            return;
        }

        // Process phantom references to detect leaks
        Reference<?> ref;
        while ((ref = referenceQueue.poll()) != null) {
            handlePhantomReference(ref);
        }

        // Check for old unclosed resources
        long now = System.currentTimeMillis();
        for (ResourceHolder holder : activeResources.values()) {
            if (!holder.closed && holder.getAge() > maxResourceAge) {
                reportPotentialLeak(holder);
            }
        }
    }

    /**
     * Perform automatic cleanup of abandoned resources
     */
    public void performCleanup() {
        if (!autoCleanupEnabled) {
            return;
        }

        int cleaned = 0;
        long now = System.currentTimeMillis();

        for (Map.Entry<String, ResourceHolder> entry : activeResources.entrySet()) {
            ResourceHolder holder = entry.getValue();

            // Check if resource is abandoned
            if (!holder.closed && !holder.isAlive()) {
                // Resource object has been garbage collected but not closed
                reportLeak(holder);
                activeResources.remove(entry.getKey());
                cleaned++;
            } else if (!holder.closed && holder.getAge() > maxResourceAge * 2) {
                // Very old unclosed resource - attempt to close it
                AutoCloseable resource = holder.resourceRef.get();
                if (resource != null) {
                    try {
                        log.warn("Auto-closing abandoned resource: {} ({}, age: {} ms)", holder.resourceId, holder.resourceType,
                                holder.getAge());
                        resource.close();
                        holder.closed = true;
                        totalReleased.incrementAndGet();
                        cleaned++;
                    } catch (Exception e) {
                        log.error("Failed to auto-close resource: {}", holder.resourceId, e);
                    }
                }
            }
        }

        if (cleaned > 0) {
            log.info("Cleaned up {} abandoned resources", cleaned);
        }
    }

    /**
     * Handle phantom reference detection
     */
    private void handlePhantomReference(Reference<?> ref) {
        // Find the resource holder by phantom reference
        for (ResourceHolder holder : activeResources.values()) {
            if (holder.phantomRef == ref) {
                if (!holder.closed) {
                    reportLeak(holder);
                }
                activeResources.remove(holder.resourceId);
                break;
            }
        }
    }

    /**
     * Report a potential resource leak
     */
    private void reportPotentialLeak(ResourceHolder holder) {
        log.warn("Potential resource leak detected: {} ({}) - open for {} ms", holder.resourceId, holder.resourceType, holder.getAge());

        if (log.isDebugEnabled() && holder.allocationStackTrace != null) {
            StringBuilder sb = new StringBuilder("Allocation stack trace:\n");
            for (StackTraceElement element : holder.allocationStackTrace) {
                sb.append("\tat ").append(element).append("\n");
            }
            log.debug(sb.toString());
        }
    }

    /**
     * Report a confirmed resource leak
     */
    private void reportLeak(ResourceHolder holder) {
        totalLeaks.incrementAndGet();
        log.error("Resource leak detected: {} ({}) - resource was garbage collected without being closed", holder.resourceId,
                holder.resourceType);

        if (holder.allocationStackTrace != null) {
            StringBuilder sb = new StringBuilder("Allocation stack trace:\n");
            for (int i = 0; i < Math.min(10, holder.allocationStackTrace.length); i++) {
                sb.append("\tat ").append(holder.allocationStackTrace[i]).append("\n");
            }
            log.error(sb.toString());
        }
    }

    /**
     * Generate a unique resource ID
     */
    private String generateResourceId(AutoCloseable resource) {
        return String.format("%s-%d-%d", resource.getClass().getSimpleName(), System.identityHashCode(resource),
                resourceIdCounter.incrementAndGet());
    }

    /**
     * Start the cleanup task
     */
    private void startCleanupTask() {
        if (cleanupTask != null) {
            cleanupTask.cancel(false);
        }

        cleanupTask = cleanupExecutor.scheduleWithFixedDelay(() -> {
            try {
                checkForLeaks();
                performCleanup();
            } catch (Exception e) {
                log.error("Error during resource cleanup", e);
            }
        }, cleanupInterval, cleanupInterval, TimeUnit.MILLISECONDS);
    }

    /**
     * Get resource statistics
     *
     * @return map of statistics
     */
    public Map<String, Object> getStatistics() {
        long active = 0;
        long closed = 0;

        for (ResourceHolder holder : activeResources.values()) {
            if (holder.closed) {
                closed++;
            } else {
                active++;
            }
        }

        return Map.of("totalAllocated", totalAllocated.get(), "totalReleased", totalReleased.get(), "totalLeaks", totalLeaks.get(),
                "activeResources", active, "closedResources", closed, "trackedResources", activeResources.size());
    }

    /**
     * Get active resource information
     *
     * @return set of active resource descriptions
     */
    public Set<String> getActiveResources() {
        Set<String> result = Collections.newSetFromMap(new ConcurrentHashMap<>());

        for (ResourceHolder holder : activeResources.values()) {
            if (!holder.closed && holder.isAlive()) {
                result.add(String.format("%s (%s, age: %d ms)", holder.resourceId, holder.resourceType, holder.getAge()));
            }
        }

        return Collections.unmodifiableSet(result);
    }

    /**
     * Configure resource manager
     *
     * @param maxAge maximum resource age in milliseconds
     * @param cleanupInterval cleanup interval in milliseconds
     * @param enableLeakDetection enable leak detection
     * @param enableAutoCleanup enable auto cleanup
     */
    public void configure(long maxAge, long cleanupInterval, boolean enableLeakDetection, boolean enableAutoCleanup) {
        this.maxResourceAge = maxAge;
        this.cleanupInterval = cleanupInterval;
        this.leakDetectionEnabled = enableLeakDetection;
        this.autoCleanupEnabled = enableAutoCleanup;

        // Restart cleanup task with new interval
        startCleanupTask();

        log.info("ResourceManager configured: maxAge={} ms, cleanupInterval={} ms, leakDetection={}, autoCleanup={}", maxAge,
                cleanupInterval, enableLeakDetection, enableAutoCleanup);
    }

    /**
     * Force cleanup of all resources
     *
     * @return number of resources cleaned
     */
    public int forceCleanup() {
        log.info("Forcing cleanup of all resources");

        int cleaned = 0;
        for (ResourceHolder holder : activeResources.values()) {
            if (!holder.closed) {
                AutoCloseable resource = holder.resourceRef.get();
                if (resource != null) {
                    try {
                        resource.close();
                        holder.closed = true;
                        cleaned++;
                    } catch (Exception e) {
                        log.error("Failed to force close resource: {}", holder.resourceId, e);
                    }
                }
            }
        }

        log.info("Force cleaned {} resources", cleaned);
        return cleaned;
    }

    /**
     * Shutdown the resource manager
     */
    public void shutdown() {
        if (shutdownInProgress) {
            return;
        }

        shutdownInProgress = true;
        log.info("Shutting down ResourceManager");

        // Cancel cleanup task
        if (cleanupTask != null) {
            cleanupTask.cancel(false);
        }

        // Force cleanup of all resources
        int cleaned = forceCleanup();

        // Shutdown executor
        cleanupExecutor.shutdown();
        try {
            if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            cleanupExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }

        // Log final statistics
        log.info("ResourceManager shutdown complete. Total allocated: {}, released: {}, leaks: {}, force cleaned: {}", totalAllocated.get(),
                totalReleased.get(), totalLeaks.get(), cleaned);
    }

    /**
     * Create a managed resource wrapper
     *
     * @param <T> resource type
     * @param resource the resource to wrap
     * @return managed resource
     */
    public <T extends AutoCloseable> ManagedResource<T> manage(T resource) {
        String resourceId = registerResource(resource);
        return new ManagedResource<>(resource, resourceId, this);
    }

    /**
     * Wrapper for managed resources
     */
    public static class ManagedResource<T extends AutoCloseable> implements AutoCloseable {
        private final T resource;
        private final String resourceId;
        private final ResourceManager manager;
        private volatile boolean closed = false;

        ManagedResource(T resource, String resourceId, ResourceManager manager) {
            this.resource = resource;
            this.resourceId = resourceId;
            this.manager = manager;
        }

        public T get() {
            if (closed) {
                throw new IllegalStateException("Resource has been closed: " + resourceId);
            }
            return resource;
        }

        @Override
        public void close() throws Exception {
            if (closed) {
                return;
            }

            try {
                resource.close();
            } finally {
                closed = true;
                manager.markClosed(resourceId);
                manager.unregisterResource(resourceId);
            }
        }
    }
}
