/*
 * © 2016 AgNO3 Gmbh & Co. KG
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
package jcifs.smb;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.Address;
import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.SmbConstants;
import jcifs.SmbTransport;
import jcifs.SmbTransportPool;
import jcifs.util.transport.TransportException;

/**
 * Implementation of the SMB transport pool for managing SMB connections.
 * Provides connection pooling and reuse for improved performance.
 *
 * @author mbechler
 *
 * <p>This class is intended for internal use.</p>
 */
public class SmbTransportPoolImpl implements SmbTransportPool {

    /**
     * Constructs a new SmbTransportPoolImpl instance.
     * This transport pool manages SMB connections for the client.
     */
    public SmbTransportPoolImpl() {
        // Start proactive health checking
        startProactiveHealthChecking();
    }

    private static final Logger log = LoggerFactory.getLogger(SmbTransportPoolImpl.class);

    private final ConcurrentLinkedQueue<SmbTransportImpl> connections = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<SmbTransportImpl> nonPooledConnections = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<SmbTransportImpl> toRemove = new ConcurrentLinkedQueue<>();
    final Map<String, Integer> failCounts = new ConcurrentHashMap<>();

    // Connection pool configuration
    private static final int DEFAULT_MAX_POOL_SIZE = 100;
    private static final int DEFAULT_MAX_IDLE_TIME = 300000; // 5 minutes in ms
    private static final int DEFAULT_HEALTH_CHECK_INTERVAL = 60000; // 1 minute in ms
    private static final int DEFAULT_PROACTIVE_CHECK_INTERVAL = 30000; // 30 seconds in ms
    private int maxPoolSize = DEFAULT_MAX_POOL_SIZE;
    private int maxIdleTime = DEFAULT_MAX_IDLE_TIME;
    private int healthCheckInterval = DEFAULT_HEALTH_CHECK_INTERVAL;
    private long lastHealthCheck = System.currentTimeMillis();

    // Advanced health monitoring
    private final ScheduledExecutorService healthCheckExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "SmbTransportPool-HealthCheck");
        t.setDaemon(true);
        return t;
    });
    private ScheduledFuture<?> healthCheckTask;
    private volatile boolean healthCheckingEnabled = true;

    // Health check metrics
    private final AtomicLong totalHealthChecks = new AtomicLong(0);
    private final AtomicLong failedHealthChecks = new AtomicLong(0);
    private final AtomicLong connectionsRemoved = new AtomicLong(0);
    private final AtomicInteger activeConnections = new AtomicInteger(0);
    private final Map<String, ConnectionMetrics> connectionMetrics = new ConcurrentHashMap<>();

    // Proactive health monitoring
    private volatile boolean proactiveHealthCheckEnabled = true;
    private final long proactiveCheckInterval = DEFAULT_PROACTIVE_CHECK_INTERVAL;

    // Connection failure tracking
    private final Map<String, Long> lastFailureTimes = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> consecutiveFailures = new ConcurrentHashMap<>();
    private static final int MAX_CONSECUTIVE_FAILURES = 3;
    private static final long FAILURE_RECOVERY_TIME = 600000; // 10 minutes

    @Override
    public SmbTransportImpl getSmbTransport(final CIFSContext tc, final Address address, final int port, final boolean nonPooled) {
        return getSmbTransport(tc, address, port, tc.getConfig().getLocalAddr(), tc.getConfig().getLocalPort(), null, nonPooled);
    }

    @Override
    public SmbTransportImpl getSmbTransport(final CIFSContext tc, final Address address, final int port, final boolean nonPooled,
            final boolean forceSigning) {
        return getSmbTransport(tc, address, port, tc.getConfig().getLocalAddr(), tc.getConfig().getLocalPort(), null, nonPooled,
                forceSigning);
    }

    @Override
    public SmbTransportImpl getSmbTransport(final CIFSContext tc, final Address address, final int port, final InetAddress localAddr,
            final int localPort, final String hostName, final boolean nonPooled) {
        return getSmbTransport(tc, address, port, localAddr, localPort, hostName, nonPooled, false);
    }

    @Override
    public SmbTransportImpl getSmbTransport(final CIFSContext tc, final Address address, int port, final InetAddress localAddr,
            final int localPort, final String hostName, final boolean nonPooled, final boolean forceSigning) {
        if (port <= 0) {
            port = SmbConstants.DEFAULT_PORT;
        }

        // Perform cleanup and health checks without global synchronization
        cleanup();
        performHealthCheck();

        if (log.isTraceEnabled()) {
            log.trace("Exclusive " + nonPooled + " enforced signing " + forceSigning);
        }

        // Check for existing connection
        if (!nonPooled && tc.getConfig().getSessionLimit() != 1) {
            final SmbTransportImpl existing = findConnection(tc, address, port, localAddr, localPort, hostName, forceSigning, false);
            if (existing != null) {
                return existing;
            }
        }

        // Check pool size limits using atomic operation
        if (!nonPooled) {
            int currentSize = this.connections.size();
            if (currentSize >= maxPoolSize) {
                // Try to remove idle connections
                removeIdleConnections();

                // If still at limit, throw exception
                if (this.connections.size() >= maxPoolSize) {
                    throw new IllegalStateException("Connection pool has reached maximum size of " + maxPoolSize
                            + ". Consider increasing pool size or closing idle connections.");
                }
            }
        }

        final SmbTransportImpl conn = new SmbTransportImpl(tc, address, port, localAddr, localPort, forceSigning);
        if (log.isDebugEnabled()) {
            log.debug("New transport connection " + conn + " (pool size: " + connections.size() + "/" + maxPoolSize + ")");
        }

        // Track connection metrics
        String key = getConnectionKey(address, port);
        connectionMetrics.computeIfAbsent(key, k -> new ConnectionMetrics()).recordConnection();
        activeConnections.incrementAndGet();

        if (nonPooled) {
            this.nonPooledConnections.offer(conn);
        } else {
            this.connections.offer(conn);
        }
        return conn;
    }

    /**
     * @param tc
     * @param address
     * @param port
     * @param localAddr
     * @param localPort
     * @param hostName
     * @param forceSigning
     * @return
     */
    private SmbTransportImpl findConnection(final CIFSContext tc, final Address address, final int port, final InetAddress localAddr,
            final int localPort, final String hostName, final boolean forceSigning, final boolean connectedOnly) {
        for (final SmbTransportImpl conn : this.connections) {
            if (conn.matches(address, port, localAddr, localPort, hostName)
                    && (tc.getConfig().getSessionLimit() == 0 || conn.getNumSessions() < tc.getConfig().getSessionLimit())) {
                try {
                    if (conn.isFailed() || connectedOnly && conn.isDisconnected()) {
                        continue;
                    }

                    if (forceSigning && !conn.isSigningEnforced()) {
                        // if signing is enforced and was not on the connection, skip
                        if (log.isTraceEnabled()) {
                            log.debug("Cannot reuse, signing enforced but connection does not have it enabled " + conn);
                        }
                        continue;
                    }

                    if (!forceSigning && !tc.getConfig().isSigningEnforced() && conn.isSigningEnforced()
                            && !conn.getNegotiateResponse().isSigningRequired()) {
                        // if signing is not enforced, dont use connections that have signing enforced
                        // for purposes that dont require it.
                        if (log.isTraceEnabled()) {
                            log.debug("Cannot reuse, signing enforced on connection " + conn);
                        }
                        continue;
                    }

                    if (!conn.getNegotiateResponse().canReuse(tc, forceSigning)) {
                        if (log.isTraceEnabled()) {
                            log.trace("Cannot reuse, different config " + conn);
                        }
                        continue;
                    }
                } catch (final CIFSException e) {
                    log.debug("Error while checking for reuse", e);
                    continue;
                }

                if (log.isTraceEnabled()) {
                    log.trace("Reusing transport connection " + conn);
                }
                return conn.acquire();
            }
        }

        return null;
    }

    @Override
    public SmbTransportImpl getSmbTransport(final CIFSContext tf, final String name, final int port, final boolean exclusive,
            final boolean forceSigning) throws IOException {

        final Address[] addrs = tf.getNameServiceClient().getAllByName(name, true);

        if (addrs == null || addrs.length == 0) {
            throw new UnknownHostException(name);
        }

        Arrays.sort(addrs, (o1, o2) -> {
            Integer fail1 = SmbTransportPoolImpl.this.failCounts.get(o1.getHostAddress());
            Integer fail2 = SmbTransportPoolImpl.this.failCounts.get(o2.getHostAddress());
            if (fail1 == null) {
                fail1 = 0;
            }
            if (fail2 == null) {
                fail2 = 0;
            }
            return Integer.compare(fail1, fail2);
        });

        // Check for existing connections without global synchronization
        for (final Address addr : addrs) {
            final SmbTransportImpl found =
                    findConnection(tf, addr, port, tf.getConfig().getLocalAddr(), tf.getConfig().getLocalPort(), name, forceSigning, true);
            if (found != null) {
                return found;
            }
        }

        IOException ex = null;
        for (final Address addr : addrs) {
            if (log.isDebugEnabled()) {
                log.debug("Trying address {}", addr);
            }
            try (SmbTransportImpl trans = getSmbTransport(tf, addr, port, exclusive, forceSigning).unwrap(SmbTransportImpl.class)) {
                try {
                    trans.ensureConnected();
                } catch (final IOException e) {
                    removeTransport(trans);
                    throw e;
                }
                return trans.acquire();
            } catch (final IOException e) {
                final String hostAddress = addr.getHostAddress();
                final Integer failCount = this.failCounts.get(hostAddress);
                if (failCount == null) {
                    this.failCounts.put(hostAddress, 1);
                } else {
                    this.failCounts.put(hostAddress, failCount + 1);
                }
                ex = e;
            }
        }

        if (ex != null) {
            throw ex;
        }
        throw new TransportException("All connection attempts failed");
    }

    /**
     * Checks if the specified transport is contained in the connection pool
     * @param trans the transport to check for
     * @return whether (non-exclusive) connection is in the pool
     */
    public boolean contains(final SmbTransport trans) {
        cleanup();
        return this.connections.contains(trans);
    }

    @Override
    public void removeTransport(final SmbTransport trans) {
        if (log.isDebugEnabled()) {
            log.debug("Scheduling transport connection for removal " + trans + " (" + System.identityHashCode(trans) + ")");
        }
        this.toRemove.add((SmbTransportImpl) trans);
    }

    private void cleanup() {
        SmbTransportImpl trans;
        while ((trans = this.toRemove.poll()) != null) {
            if (log.isDebugEnabled()) {
                log.debug("Removing transport connection " + trans + " (" + System.identityHashCode(trans) + ")");
            }
            this.connections.remove(trans);
            this.nonPooledConnections.remove(trans);
            activeConnections.decrementAndGet();
            connectionsRemoved.incrementAndGet();
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbTransportPool#close()
     */
    @Override
    public boolean close() throws CIFSException {
        boolean inUse = false;

        // Cleanup first
        cleanup();
        log.debug("Closing pool");

        // Create a snapshot of connections to close
        List<SmbTransportImpl> toClose = new ArrayList<>(this.connections);
        toClose.addAll(this.nonPooledConnections);

        // Clear the collections (thread-safe operations)
        this.connections.clear();
        this.nonPooledConnections.clear();
        this.activeConnections.set(0);

        // Close all connections outside of synchronization
        for (final SmbTransportImpl conn : toClose) {
            try {
                inUse |= conn.disconnect(false, false);
            } catch (final IOException e) {
                log.warn("Failed to close connection", e);
            }
        }

        // Final cleanup
        cleanup();
        return inUse;
    }

    @Override
    public byte[] getChallenge(final CIFSContext tf, final Address dc) throws SmbException {
        return getChallenge(tf, dc, 0);
    }

    @Override
    public byte[] getChallenge(final CIFSContext tf, final Address dc, final int port) throws SmbException {
        try (SmbTransportInternal trans = tf.getTransportPool()
                .getSmbTransport(tf, dc, port, false, !tf.getCredentials().isAnonymous() && tf.getConfig().isIpcSigningEnforced())
                .unwrap(SmbTransportInternal.class)) {
            trans.ensureConnected();
            return trans.getServerEncryptionKey();
        } catch (final SmbException e) {
            throw e;
        } catch (final IOException e) {
            throw new SmbException("Connection failed", e);
        }
    }

    @Override
    public void logon(final CIFSContext tf, final Address dc) throws SmbException {
        logon(tf, dc, 0);
    }

    @Override
    @Deprecated
    public void logon(final CIFSContext tf, final Address dc, final int port) throws SmbException {
        try (SmbTransportInternal smbTransport = tf.getTransportPool()
                .getSmbTransport(tf, dc, port, false, tf.getConfig().isIpcSigningEnforced())
                .unwrap(SmbTransportInternal.class);
                SmbSessionInternal smbSession = smbTransport.getSmbSession(tf, dc.getHostName(), null).unwrap(SmbSessionInternal.class);
                SmbTreeInternal tree = smbSession.getSmbTree(tf.getConfig().getLogonShare(), null).unwrap(SmbTreeInternal.class)) {
            tree.connectLogon(tf);
        }
    }

    /**
     * Perform health check on connections
     */
    private void performHealthCheck() {
        long now = System.currentTimeMillis();
        if (now - lastHealthCheck < healthCheckInterval) {
            return;
        }

        lastHealthCheck = now;
        totalHealthChecks.incrementAndGet();
        List<SmbTransportImpl> unhealthy = new ArrayList<>();

        for (SmbTransportImpl transport : connections) {
            try {
                // Perform comprehensive health check
                if (isConnectionUnhealthy(transport)) {
                    unhealthy.add(transport);
                    String key = getConnectionKey(transport);
                    recordConnectionFailure(key);
                    log.debug("Removing unhealthy connection: {}", transport);
                }
            } catch (Exception e) {
                log.debug("Error checking connection health: {}", e.getMessage());
                unhealthy.add(transport);
                failedHealthChecks.incrementAndGet();
            }
        }

        // Remove unhealthy connections
        for (SmbTransportImpl transport : unhealthy) {
            connections.remove(transport);
            activeConnections.decrementAndGet();
            connectionsRemoved.incrementAndGet();

            try {
                transport.disconnect(true, true);
            } catch (Exception e) {
                log.debug("Error disconnecting unhealthy transport: {}", e.getMessage());
            }
        }

        if (!unhealthy.isEmpty()) {
            log.info("Removed {} unhealthy connections from pool", unhealthy.size());
        }

        // Perform maintenance tasks
        performMaintenanceTasks();
    }

    /**
     * Remove idle connections to free up pool space
     */
    private void removeIdleConnections() {
        long now = System.currentTimeMillis();
        List<SmbTransportImpl> idle = new ArrayList<>();

        // Iterate through connections without synchronization - ConcurrentLinkedQueue is thread-safe
        for (SmbTransportImpl transport : connections) {
            try {
                // Check if connection has been idle too long
                // Note: getLastUseTime() method would need to be added to SmbTransportImpl
                // For now, we'll use a simple disconnected check
                if (transport.isDisconnected()) {
                    idle.add(transport);
                    log.debug("Removing idle connection: {}", transport);
                }
            } catch (Exception e) {
                log.debug("Error checking connection idle time: {}", e.getMessage());
            }
        }

        // Remove at most half of the idle connections
        int toRemoveCount = Math.min(idle.size(), Math.max(1, idle.size() / 2));
        for (int i = 0; i < toRemoveCount; i++) {
            SmbTransportImpl transport = idle.get(i);
            if (connections.remove(transport)) {
                activeConnections.decrementAndGet();
                connectionsRemoved.incrementAndGet();
                try {
                    transport.disconnect(true, true);
                } catch (Exception e) {
                    log.debug("Error disconnecting idle transport: {}", e.getMessage());
                }
            }
        }

        if (toRemoveCount > 0) {
            log.info("Removed {} idle connections from pool", toRemoveCount);
        }
    }

    /**
     * Set the maximum pool size
     * @param size the maximum number of connections in the pool
     */
    public void setMaxPoolSize(int size) {
        if (size <= 0) {
            throw new IllegalArgumentException("Pool size must be positive");
        }
        this.maxPoolSize = size;
        log.info("Set maximum pool size to {}", size);
    }

    /**
     * Set the maximum idle time for connections
     * @param millis the maximum idle time in milliseconds
     */
    public void setMaxIdleTime(int millis) {
        if (millis <= 0) {
            throw new IllegalArgumentException("Idle time must be positive");
        }
        this.maxIdleTime = millis;
        log.info("Set maximum idle time to {} ms", millis);
    }

    /**
     * Set the health check interval
     * @param millis the health check interval in milliseconds
     */
    public void setHealthCheckInterval(int millis) {
        if (millis <= 0) {
            throw new IllegalArgumentException("Health check interval must be positive");
        }
        this.healthCheckInterval = millis;
        log.info("Set health check interval to {} ms", millis);
    }

    /**
     * Get current pool statistics
     * @return pool statistics string
     */
    public String getPoolStatistics() {
        return String.format("Pool statistics: Active=%d, NonPooled=%d, MaxSize=%d, Failures=%d, HealthChecks=%d, Removed=%d",
                connections.size(), nonPooledConnections.size(), maxPoolSize, failCounts.size(), totalHealthChecks.get(),
                connectionsRemoved.get());
    }

    // Enhanced health checking methods

    /**
     * Start proactive health checking
     */
    private void startProactiveHealthChecking() {
        if (proactiveHealthCheckEnabled && healthCheckTask == null) {
            healthCheckTask = healthCheckExecutor.scheduleWithFixedDelay(this::performProactiveHealthCheck, proactiveCheckInterval,
                    proactiveCheckInterval, TimeUnit.MILLISECONDS);
            log.info("Started proactive health checking with interval {} ms", proactiveCheckInterval);
        }
    }

    /**
     * Stop proactive health checking
     */
    public void stopProactiveHealthChecking() {
        if (healthCheckTask != null) {
            healthCheckTask.cancel(false);
            healthCheckTask = null;
            log.info("Stopped proactive health checking");
        }
    }

    /**
     * Perform proactive health check on all connections
     */
    private void performProactiveHealthCheck() {
        if (!proactiveHealthCheckEnabled) {
            return;
        }

        try {
            performHealthCheck();
        } catch (Exception e) {
            log.warn("Error during proactive health check: {}", e.getMessage());
        }
    }

    /**
     * Check if a connection is unhealthy using comprehensive checks
     */
    private boolean isConnectionUnhealthy(SmbTransportImpl transport) {
        try {
            // Basic disconnection check
            if (transport.isDisconnected()) {
                return true;
            }

            // Check if transport is failed
            if (transport.isFailed()) {
                return true;
            }

            // Check for consecutive failures
            String key = getConnectionKey(transport);
            AtomicInteger failures = consecutiveFailures.get(key);
            if (failures != null && failures.get() >= MAX_CONSECUTIVE_FAILURES) {
                Long lastFailure = lastFailureTimes.get(key);
                if (lastFailure != null && System.currentTimeMillis() - lastFailure < FAILURE_RECOVERY_TIME) {
                    return true;
                }
            }

            return false;
        } catch (Exception e) {
            log.debug("Error checking connection health for {}: {}", transport, e.getMessage());
            return true;
        }
    }

    /**
     * Get connection key for tracking
     */
    private String getConnectionKey(SmbTransportImpl transport) {
        // Use toString() method which includes port information
        // Format is typically: Transport[address:port,state=...]
        String transportStr = transport.toString();
        int startBracket = transportStr.indexOf('[');
        int endBracket = transportStr.indexOf(',');
        if (startBracket != -1 && endBracket != -1 && endBracket > startBracket) {
            return transportStr.substring(startBracket + 1, endBracket);
        }
        // Fallback: just use address
        return transport.getRemoteAddress().getHostAddress();
    }

    /**
     * Get connection key from address and port
     */
    private String getConnectionKey(Address address, int port) {
        return address.getHostAddress() + ":" + port;
    }

    /**
     * Record connection failure for tracking
     */
    private void recordConnectionFailure(String key) {
        lastFailureTimes.put(key, System.currentTimeMillis());
        consecutiveFailures.computeIfAbsent(key, k -> new AtomicInteger(0)).incrementAndGet();

        ConnectionMetrics metrics = connectionMetrics.get(key);
        if (metrics != null) {
            metrics.recordFailure();
        }
    }

    /**
     * Record connection success for recovery tracking
     */
    private void recordConnectionSuccess(String key) {
        consecutiveFailures.remove(key);
        lastFailureTimes.remove(key);

        ConnectionMetrics metrics = connectionMetrics.get(key);
        if (metrics != null) {
            metrics.recordSuccess();
        }
    }

    /**
     * Perform maintenance tasks during health checks
     */
    private void performMaintenanceTasks() {
        // Clean up old failure records
        long now = System.currentTimeMillis();
        lastFailureTimes.entrySet().removeIf(entry -> now - entry.getValue() > FAILURE_RECOVERY_TIME * 2);

        // Clean up old consecutive failure counters
        consecutiveFailures.entrySet().removeIf(entry -> {
            String key = entry.getKey();
            Long lastFailure = lastFailureTimes.get(key);
            return lastFailure == null || now - lastFailure > FAILURE_RECOVERY_TIME * 2;
        });

        // Update connection metrics
        updateConnectionMetrics();
    }

    /**
     * Update connection metrics for monitoring
     */
    private void updateConnectionMetrics() {
        // Clean up metrics for connections that no longer exist
        connectionMetrics.entrySet().removeIf(entry -> {
            String key = entry.getKey();
            boolean exists = connections.stream().anyMatch(conn -> getConnectionKey(conn).equals(key));
            return !exists;
        });
    }

    /**
     * Get detailed health statistics
     */
    public PoolHealthMetrics getHealthMetrics() {
        return new PoolHealthMetrics(connections.size(), nonPooledConnections.size(), activeConnections.get(), maxPoolSize,
                totalHealthChecks.get(), failedHealthChecks.get(), connectionsRemoved.get(), connectionMetrics.size(),
                healthCheckingEnabled, proactiveHealthCheckEnabled);
    }

    /**
     * Enable or disable health checking
     */
    public void setHealthCheckingEnabled(boolean enabled) {
        this.healthCheckingEnabled = enabled;
        if (enabled) {
            startProactiveHealthChecking();
        } else {
            stopProactiveHealthChecking();
        }
        log.info("Health checking {}", enabled ? "enabled" : "disabled");
    }

    /**
     * Enable or disable proactive health checking
     */
    public void setProactiveHealthCheckEnabled(boolean enabled) {
        this.proactiveHealthCheckEnabled = enabled;
        if (enabled && healthCheckingEnabled) {
            startProactiveHealthChecking();
        } else if (!enabled) {
            stopProactiveHealthChecking();
        }
        log.info("Proactive health checking {}", enabled ? "enabled" : "disabled");
    }

    /**
     * Close the transport pool and cleanup resources
     */
    public void closePool() {
        stopProactiveHealthChecking();
        healthCheckExecutor.shutdown();
        try {
            if (!healthCheckExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                healthCheckExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            healthCheckExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }

        // Close all connections without synchronization - concurrent collections are thread-safe
        connections.forEach(conn -> {
            try {
                conn.disconnect(true, true);
            } catch (Exception e) {
                log.debug("Error closing connection: {}", e.getMessage());
            }
        });
        connections.clear();

        nonPooledConnections.forEach(conn -> {
            try {
                conn.disconnect(true, true);
            } catch (Exception e) {
                log.debug("Error closing non-pooled connection: {}", e.getMessage());
            }
        });
        nonPooledConnections.clear();

        activeConnections.set(0);
        log.info("Transport pool closed");
    }

    /**
     * Connection metrics for monitoring individual connections
     */
    private static class ConnectionMetrics {
        private final AtomicLong connectionsCreated = new AtomicLong(0);
        private final AtomicLong successCount = new AtomicLong(0);
        private final AtomicLong failureCount = new AtomicLong(0);
        private volatile long firstConnectionTime = System.currentTimeMillis();
        private volatile long lastActivityTime = System.currentTimeMillis();

        void recordConnection() {
            connectionsCreated.incrementAndGet();
            lastActivityTime = System.currentTimeMillis();
        }

        void recordSuccess() {
            successCount.incrementAndGet();
            lastActivityTime = System.currentTimeMillis();
        }

        void recordFailure() {
            failureCount.incrementAndGet();
            lastActivityTime = System.currentTimeMillis();
        }

        public long getConnectionsCreated() {
            return connectionsCreated.get();
        }

        public long getSuccessCount() {
            return successCount.get();
        }

        public long getFailureCount() {
            return failureCount.get();
        }

        public long getFirstConnectionTime() {
            return firstConnectionTime;
        }

        public long getLastActivityTime() {
            return lastActivityTime;
        }

        public double getSuccessRate() {
            long total = successCount.get() + failureCount.get();
            return total > 0 ? (double) successCount.get() / total : 1.0;
        }
    }

    /**
     * Pool health metrics for monitoring
     */
    public static class PoolHealthMetrics {
        private final int activeConnections;
        private final int nonPooledConnections;
        private final int trackedConnections;
        private final int maxPoolSize;
        private final long totalHealthChecks;
        private final long failedHealthChecks;
        private final long connectionsRemoved;
        private final int uniqueEndpoints;
        private final boolean healthCheckingEnabled;
        private final boolean proactiveHealthCheckEnabled;

        public PoolHealthMetrics(int activeConnections, int nonPooledConnections, int trackedConnections, int maxPoolSize,
                long totalHealthChecks, long failedHealthChecks, long connectionsRemoved, int uniqueEndpoints,
                boolean healthCheckingEnabled, boolean proactiveHealthCheckEnabled) {
            this.activeConnections = activeConnections;
            this.nonPooledConnections = nonPooledConnections;
            this.trackedConnections = trackedConnections;
            this.maxPoolSize = maxPoolSize;
            this.totalHealthChecks = totalHealthChecks;
            this.failedHealthChecks = failedHealthChecks;
            this.connectionsRemoved = connectionsRemoved;
            this.uniqueEndpoints = uniqueEndpoints;
            this.healthCheckingEnabled = healthCheckingEnabled;
            this.proactiveHealthCheckEnabled = proactiveHealthCheckEnabled;
        }

        // Getters
        public int getActiveConnections() {
            return activeConnections;
        }

        public int getNonPooledConnections() {
            return nonPooledConnections;
        }

        public int getTrackedConnections() {
            return trackedConnections;
        }

        public int getMaxPoolSize() {
            return maxPoolSize;
        }

        public long getTotalHealthChecks() {
            return totalHealthChecks;
        }

        public long getFailedHealthChecks() {
            return failedHealthChecks;
        }

        public long getConnectionsRemoved() {
            return connectionsRemoved;
        }

        public int getUniqueEndpoints() {
            return uniqueEndpoints;
        }

        public boolean isHealthCheckingEnabled() {
            return healthCheckingEnabled;
        }

        public boolean isProactiveHealthCheckEnabled() {
            return proactiveHealthCheckEnabled;
        }

        public double getHealthCheckSuccessRate() {
            return totalHealthChecks > 0 ? 1.0 - ((double) failedHealthChecks / totalHealthChecks) : 1.0;
        }

        public double getPoolUtilization() {
            return maxPoolSize > 0 ? (double) activeConnections / maxPoolSize : 0.0;
        }

        @Override
        public String toString() {
            return String.format(
                    "PoolHealthMetrics[active=%d, nonPooled=%d, tracked=%d, max=%d, "
                            + "healthChecks=%d, failed=%d, removed=%d, endpoints=%d, "
                            + "healthCheckEnabled=%s, proactiveEnabled=%s, utilization=%.2f%%, successRate=%.2f%%]",
                    activeConnections, nonPooledConnections, trackedConnections, maxPoolSize, totalHealthChecks, failedHealthChecks,
                    connectionsRemoved, uniqueEndpoints, healthCheckingEnabled, proactiveHealthCheckEnabled, getPoolUtilization() * 100,
                    getHealthCheckSuccessRate() * 100);
        }
    }

}
