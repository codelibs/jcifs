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
package jcifs.smb;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSException;
import jcifs.Configuration;

/**
 * SMB3 Multi-Channel Manager.
 *
 * Manages multiple network connections for improved performance and redundancy
 * as specified in the SMB 3.x multi-channel feature.
 */
public class MultiChannelManager {

    private static final Logger log = LoggerFactory.getLogger(MultiChannelManager.class);

    // Multi-channel configuration
    private final Configuration config;
    private final int maxChannels;
    private final LoadBalancingStrategy loadBalancingStrategy;
    private final long healthCheckInterval;

    // Channel management
    private final ConcurrentMap<String, ChannelGroup> sessionChannels = new ConcurrentHashMap<>();
    private final ExecutorService channelExecutor;
    private final ScheduledExecutorService healthCheckExecutor;

    // Statistics
    private final AtomicLong totalRequests = new AtomicLong(0);
    private final AtomicLong totalChannelsCreated = new AtomicLong(0);

    /**
     * Load balancing strategies for distributing operations across channels.
     */
    public enum LoadBalancingStrategy {
        /** Round-robin distribution */
        ROUND_ROBIN,
        /** Least connections */
        LEAST_CONNECTIONS,
        /** Random selection */
        RANDOM,
        /** Failover only (use primary until failure) */
        FAILOVER_ONLY
    }

    /**
     * Represents a group of channels for a single session.
     */
    public static class ChannelGroup {
        private final String sessionId;
        private final List<ChannelInfo> channels = new CopyOnWriteArrayList<>();
        private final AtomicInteger roundRobinIndex = new AtomicInteger(0);
        private volatile ChannelInfo primaryChannel;

        public ChannelGroup(String sessionId) {
            this.sessionId = sessionId;
        }

        public String getSessionId() {
            return sessionId;
        }

        public List<ChannelInfo> getChannels() {
            return new ArrayList<>(channels);
        }

        public void addChannel(ChannelInfo channel) {
            channels.add(channel);
            if (primaryChannel == null) {
                primaryChannel = channel;
            }
        }

        public void removeChannel(ChannelInfo channel) {
            channels.remove(channel);
            if (primaryChannel == channel && !channels.isEmpty()) {
                primaryChannel = channels.get(0);
            }
        }

        public ChannelInfo getPrimaryChannel() {
            return primaryChannel;
        }

        public int getChannelCount() {
            return channels.size();
        }

        public ChannelInfo selectChannel(LoadBalancingStrategy strategy) {
            if (channels.isEmpty()) {
                return null;
            }

            switch (strategy) {
            case ROUND_ROBIN:
                int index = roundRobinIndex.getAndIncrement() % channels.size();
                return channels.get(index);

            case LEAST_CONNECTIONS:
                return channels.stream()
                        .min((c1, c2) -> Integer.compare(c1.getActiveConnections(), c2.getActiveConnections()))
                        .orElse(channels.get(0));

            case RANDOM:
                return channels.get((int) (Math.random() * channels.size()));

            case FAILOVER_ONLY:
            default:
                return primaryChannel != null ? primaryChannel : channels.get(0);
            }
        }
    }

    /**
     * Information about a single channel.
     */
    public static class ChannelInfo {
        private final String channelId;
        private final InetAddress localAddress;
        private final InetAddress remoteAddress;
        private final NetworkInterface networkInterface;
        private final SmbTransportImpl transport;
        private final AtomicInteger activeConnections = new AtomicInteger(0);
        private volatile boolean isHealthy = true;
        private volatile long lastHealthCheck = System.currentTimeMillis();

        public ChannelInfo(String channelId, InetAddress localAddress, InetAddress remoteAddress, NetworkInterface networkInterface,
                SmbTransportImpl transport) {
            this.channelId = channelId;
            this.localAddress = localAddress;
            this.remoteAddress = remoteAddress;
            this.networkInterface = networkInterface;
            this.transport = transport;
        }

        public String getChannelId() {
            return channelId;
        }

        public InetAddress getLocalAddress() {
            return localAddress;
        }

        public InetAddress getRemoteAddress() {
            return remoteAddress;
        }

        public NetworkInterface getNetworkInterface() {
            return networkInterface;
        }

        public SmbTransportImpl getTransport() {
            return transport;
        }

        public int getActiveConnections() {
            return activeConnections.get();
        }

        public void incrementConnections() {
            activeConnections.incrementAndGet();
        }

        public void decrementConnections() {
            activeConnections.decrementAndGet();
        }

        public boolean isHealthy() {
            return isHealthy;
        }

        public void setHealthy(boolean healthy) {
            this.isHealthy = healthy;
            this.lastHealthCheck = System.currentTimeMillis();
        }

        public long getLastHealthCheck() {
            return lastHealthCheck;
        }

        @Override
        public String toString() {
            return String.format("ChannelInfo{id=%s, local=%s, remote=%s, active=%d, healthy=%s}", channelId, localAddress, remoteAddress,
                    activeConnections.get(), isHealthy);
        }
    }

    /**
     * Constructs a MultiChannelManager with the given configuration.
     *
     * @param config the configuration
     */
    public MultiChannelManager(Configuration config) {
        this.config = config;
        this.maxChannels = getMaxChannelsFromConfig(config);
        this.loadBalancingStrategy = getLoadBalancingStrategyFromConfig(config);
        this.healthCheckInterval = getHealthCheckIntervalFromConfig(config);

        // Create thread pools
        this.channelExecutor = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "SMB3-MultiChannel-Worker");
            t.setDaemon(true);
            return t;
        });

        this.healthCheckExecutor = Executors.newScheduledThreadPool(2, r -> {
            Thread t = new Thread(r, "SMB3-MultiChannel-HealthCheck");
            t.setDaemon(true);
            return t;
        });

        // Start health check task
        if (healthCheckInterval > 0) {
            startHealthCheckTask();
        }

        log.info("MultiChannelManager initialized with maxChannels={}, strategy={}, healthCheckInterval={}ms", maxChannels,
                loadBalancingStrategy, healthCheckInterval);
    }

    /**
     * Creates channels for a new session.
     *
     * @param sessionId the session identifier
     * @param serverAddresses available server addresses for multi-channel
     * @return the created channel group
     * @throws CIFSException if channel creation fails
     */
    public ChannelGroup createChannels(String sessionId, List<InetAddress> serverAddresses) throws CIFSException {
        if (sessionId == null || sessionId.isEmpty()) {
            throw new CIFSException("Session ID cannot be null or empty");
        }

        ChannelGroup channelGroup = new ChannelGroup(sessionId);
        sessionChannels.put(sessionId, channelGroup);

        try {
            // Get available network interfaces
            List<NetworkInterface> availableInterfaces = getAvailableNetworkInterfaces();

            int channelsToCreate = Math.min(maxChannels, Math.min(serverAddresses.size(), availableInterfaces.size()));
            log.debug("Creating {} channels for session {}", channelsToCreate, sessionId);

            for (int i = 0; i < channelsToCreate && i < availableInterfaces.size() && i < serverAddresses.size(); i++) {
                try {
                    NetworkInterface netInterface = availableInterfaces.get(i);
                    InetAddress serverAddress = serverAddresses.get(i);
                    InetAddress localAddress = getLocalAddressForInterface(netInterface);

                    if (localAddress != null) {
                        String channelId = sessionId + "-channel-" + i;

                        // Create transport for this channel (simplified - in real implementation would be more complex)
                        SmbTransportImpl transport = createChannelTransport(localAddress, serverAddress);

                        ChannelInfo channel = new ChannelInfo(channelId, localAddress, serverAddress, netInterface, transport);
                        channelGroup.addChannel(channel);
                        totalChannelsCreated.incrementAndGet();

                        log.debug("Created channel {} for session {}: {} -> {}", channelId, sessionId, localAddress, serverAddress);
                    }
                } catch (Exception e) {
                    log.warn("Failed to create channel {} for session {}: {}", i, sessionId, e.getMessage());
                }
            }

            if (channelGroup.getChannelCount() == 0) {
                throw new CIFSException("Failed to create any channels for session " + sessionId);
            }

            log.info("Created {} channels for session {}", channelGroup.getChannelCount(), sessionId);
            return channelGroup;

        } catch (Exception e) {
            sessionChannels.remove(sessionId);
            throw new CIFSException("Failed to create channels for session " + sessionId, e);
        }
    }

    /**
     * Selects the best channel for an operation.
     *
     * @param sessionId the session identifier
     * @return the selected channel, or null if no channels available
     */
    public ChannelInfo selectChannel(String sessionId) {
        ChannelGroup channelGroup = sessionChannels.get(sessionId);
        if (channelGroup == null) {
            log.warn("No channel group found for session {}", sessionId);
            return null;
        }

        ChannelInfo selected = channelGroup.selectChannel(loadBalancingStrategy);
        if (selected != null && selected.isHealthy()) {
            totalRequests.incrementAndGet();
            selected.incrementConnections();
            log.debug("Selected channel {} for session {} (active connections: {})", selected.getChannelId(), sessionId,
                    selected.getActiveConnections());
        }

        return selected;
    }

    /**
     * Releases a channel after use.
     *
     * @param channel the channel to release
     */
    public void releaseChannel(ChannelInfo channel) {
        if (channel != null) {
            channel.decrementConnections();
            log.debug("Released channel {} (active connections: {})", channel.getChannelId(), channel.getActiveConnections());
        }
    }

    /**
     * Removes all channels for a session.
     *
     * @param sessionId the session identifier
     */
    public void removeChannels(String sessionId) {
        ChannelGroup channelGroup = sessionChannels.remove(sessionId);
        if (channelGroup != null) {
            for (ChannelInfo channel : channelGroup.getChannels()) {
                try {
                    if (channel.getTransport() != null) {
                        channel.getTransport().disconnect(true);
                    }
                } catch (Exception e) {
                    log.warn("Error closing channel {}: {}", channel.getChannelId(), e.getMessage());
                }
            }
            log.info("Removed {} channels for session {}", channelGroup.getChannelCount(), sessionId);
        }
    }

    /**
     * Gets statistics for the multi-channel manager.
     *
     * @return channel statistics
     */
    public ChannelStatistics getStatistics() {
        return new ChannelStatistics(sessionChannels.size(),
                sessionChannels.values().stream().mapToInt(ChannelGroup::getChannelCount).sum(), totalRequests.get(),
                totalChannelsCreated.get());
    }

    /**
     * Channel statistics.
     */
    public static class ChannelStatistics {
        private final int activeSessions;
        private final int totalChannels;
        private final long totalRequests;
        private final long totalChannelsCreated;

        public ChannelStatistics(int activeSessions, int totalChannels, long totalRequests, long totalChannelsCreated) {
            this.activeSessions = activeSessions;
            this.totalChannels = totalChannels;
            this.totalRequests = totalRequests;
            this.totalChannelsCreated = totalChannelsCreated;
        }

        public int getActiveSessions() {
            return activeSessions;
        }

        public int getTotalChannels() {
            return totalChannels;
        }

        public long getTotalRequests() {
            return totalRequests;
        }

        public long getTotalChannelsCreated() {
            return totalChannelsCreated;
        }

        @Override
        public String toString() {
            return String.format("ChannelStatistics{sessions=%d, channels=%d, requests=%d, created=%d}", activeSessions, totalChannels,
                    totalRequests, totalChannelsCreated);
        }
    }

    /**
     * Cleanup and shutdown the multi-channel manager.
     */
    public void shutdown() {
        log.info("Shutting down MultiChannelManager");

        // Close all channels
        for (String sessionId : new ArrayList<>(sessionChannels.keySet())) {
            removeChannels(sessionId);
        }

        // Shutdown thread pools
        healthCheckExecutor.shutdown();
        channelExecutor.shutdown();

        try {
            if (!healthCheckExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                healthCheckExecutor.shutdownNow();
            }
            if (!channelExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                channelExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // Private helper methods

    private int getMaxChannelsFromConfig(Configuration config) {
        // In a real implementation, this would read from configuration
        return 4; // Default to 4 channels
    }

    private LoadBalancingStrategy getLoadBalancingStrategyFromConfig(Configuration config) {
        // In a real implementation, this would read from configuration
        return LoadBalancingStrategy.ROUND_ROBIN;
    }

    private long getHealthCheckIntervalFromConfig(Configuration config) {
        // In a real implementation, this would read from configuration
        return 30000; // 30 seconds
    }

    private List<NetworkInterface> getAvailableNetworkInterfaces() {
        try {
            List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
            interfaces.removeIf(ni -> {
                try {
                    return ni.isLoopback() || !ni.isUp() || ni.isVirtual();
                } catch (Exception e) {
                    return true;
                }
            });
            return interfaces;
        } catch (Exception e) {
            log.warn("Failed to get network interfaces: {}", e.getMessage());
            return Collections.emptyList();
        }
    }

    private InetAddress getLocalAddressForInterface(NetworkInterface netInterface) {
        return netInterface.getInetAddresses().nextElement();
    }

    private SmbTransportImpl createChannelTransport(InetAddress localAddress, InetAddress serverAddress) throws CIFSException {
        try {
            // Create Address wrapper for server address
            jcifs.netbios.UniAddress serverUniAddress = new jcifs.netbios.UniAddress(serverAddress);

            // Use default SMB port
            int port = 445;

            // Use default local port (0 means system assigns)
            int localPort = 0;

            // Get CIFSContext from configuration - this is a simplified approach
            // In a real implementation, this should be passed from the session context
            jcifs.CIFSContext context = createDefaultContext();

            // Create transport with multi-channel specific settings
            // Multi-channel transports should use signing consistently with the main session
            boolean forceSigning = context.getConfig().isSigningEnforced();

            SmbTransportImpl transport = new SmbTransportImpl(context, serverUniAddress, port, localAddress, localPort, forceSigning);

            // Ensure the transport is connected and ready
            transport.ensureConnected();

            // Verify multi-channel capability (SMB3+ required)
            if (!transport.isSMB2() || !transport.hasCapability(0x00000008)) { // SMB2_GLOBAL_CAP_MULTI_CHANNEL
                throw new CIFSException("Server does not support SMB multi-channel capability");
            }

            log.info("Created multi-channel transport: {} -> {}", localAddress, serverAddress);
            return transport;

        } catch (Exception e) {
            log.error("Failed to create multi-channel transport from {} to {}: {}", localAddress, serverAddress, e.getMessage());
            throw new CIFSException("Failed to create multi-channel transport: " + e.getMessage(), e);
        }
    }

    /**
     * Creates a default CIFSContext for multi-channel operations.
     * In a production implementation, this should be replaced with proper context sharing
     * from the main session to ensure consistent authentication and configuration.
     */
    private jcifs.CIFSContext createDefaultContext() throws CIFSException {
        try {
            // Use the configuration from the MultiChannelManager
            return new jcifs.context.BaseContext(this.config);
        } catch (Exception e) {
            throw new CIFSException("Failed to create CIFSContext for multi-channel transport", e);
        }
    }

    private void startHealthCheckTask() {
        healthCheckExecutor.scheduleWithFixedDelay(this::performHealthCheck, healthCheckInterval, healthCheckInterval,
                TimeUnit.MILLISECONDS);
    }

    private void performHealthCheck() {
        log.debug("Performing multi-channel health check");

        for (ChannelGroup channelGroup : sessionChannels.values()) {
            for (ChannelInfo channel : channelGroup.getChannels()) {
                try {
                    // Simplified health check - in real implementation would ping the channel
                    boolean isHealthy = checkChannelHealth(channel);
                    channel.setHealthy(isHealthy);

                    if (!isHealthy) {
                        log.warn("Channel {} is unhealthy", channel.getChannelId());
                    }
                } catch (Exception e) {
                    log.warn("Health check failed for channel {}: {}", channel.getChannelId(), e.getMessage());
                    channel.setHealthy(false);
                }
            }
        }
    }

    private boolean checkChannelHealth(ChannelInfo channel) {
        // Simplified health check - in real implementation would send a ping/echo
        return channel.getTransport() != null;
    }
}
