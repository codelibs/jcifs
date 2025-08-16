# Multi-Channel Feature - Detailed Design Document

## 1. Overview

SMB3 Multi-Channel enables the use of multiple network connections between client and server, providing increased throughput, network fault tolerance, and automatic failover capabilities. This feature aggregates bandwidth across multiple NICs and provides seamless failover when network paths fail.

## 2. Protocol Specification Reference

- **MS-SMB2 Section 3.2.4.23**: FSCTL_QUERY_NETWORK_INTERFACE_INFO
- **MS-SMB2 Section 3.2.5.14.8**: Sending an SMB2 IOCTL Request for FSCTL_QUERY_NETWORK_INTERFACE_INFO
- **MS-SMB2 Section 3.1.5.3**: Receiving an SMB_COM_NEGOTIATE
- **MS-SMB2 Section 3.2.4.1.6**: Alternative Channel Creation
- **MS-SMB2 Section 3.3.5.15.12**: Channel Binding

## 3. Multi-Channel Architecture

### 3.1 Channel States
```java
public enum ChannelState {
    DISCONNECTED(0),     // Not connected
    CONNECTING(1),       // Connection in progress
    AUTHENTICATING(2),   // Authentication in progress
    ESTABLISHED(3),      // Ready for use
    BINDING(4),         // Channel binding in progress
    ACTIVE(5),          // Actively transferring data
    FAILED(6),          // Connection failed
    CLOSING(7);         // Closing connection
    
    private final int value;
    
    ChannelState(int value) {
        this.value = value;
    }
}
```

### 3.2 Channel Capabilities
```java
public class Smb2ChannelCapabilities {
    // Multi-channel specific capabilities
    public static final int SMB2_GLOBAL_CAP_MULTI_CHANNEL = 0x00000008;
    
    // Channel binding policies
    public static final int CHANNEL_BINDING_DISABLED = 0;
    public static final int CHANNEL_BINDING_PREFERRED = 1;
    public static final int CHANNEL_BINDING_REQUIRED = 2;
    
    // Maximum channels per session
    public static final int DEFAULT_MAX_CHANNELS = 4;
    public static final int ABSOLUTE_MAX_CHANNELS = 32;
}
```

## 4. Data Structures

### 4.1 Network Interface Information
```java
package jcifs.internal.smb2.multichannel;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.List;

public class NetworkInterfaceInfo {
    private int interfaceIndex;
    private int capability;
    private int linkSpeed;  // In units of 1 Mbps
    private byte[] sockaddrStorage;  // Socket address
    private InetAddress address;
    private boolean ipv6;
    private boolean rssCapable;  // Receive Side Scaling
    private boolean rdmaCapable;
    
    // Capability flags
    public static final int NETWORK_INTERFACE_CAP_RSS = 0x00000001;
    public static final int NETWORK_INTERFACE_CAP_RDMA = 0x00000002;
    
    public NetworkInterfaceInfo(InetAddress address, int linkSpeed) {
        this.address = address;
        this.linkSpeed = linkSpeed;
        this.ipv6 = address.getAddress().length == 16;
        this.capability = 0;
        
        // Check for RSS capability (simplified - would need OS-specific checks)
        this.rssCapable = checkRSSCapability();
        if (rssCapable) {
            this.capability |= NETWORK_INTERFACE_CAP_RSS;
        }
    }
    
    public boolean isUsableForChannel() {
        return address != null && !address.isLoopbackAddress() 
            && !address.isLinkLocalAddress();
    }
    
    public int getScore() {
        // Score interface for selection (higher is better)
        int score = linkSpeed;  // Base score is link speed
        
        if (rssCapable) score += 1000;   // Prefer RSS-capable
        if (rdmaCapable) score += 2000;  // Prefer RDMA-capable
        if (!ipv6) score += 100;         // Slight preference for IPv4
        
        return score;
    }
    
    private boolean checkRSSCapability() {
        // Platform-specific RSS detection
        // Simplified implementation
        try {
            NetworkInterface ni = NetworkInterface.getByInetAddress(address);
            return ni != null && ni.supportsMulticast();
        } catch (Exception e) {
            return false;
        }
    }
    
    public byte[] encode() {
        // Encode for FSCTL_QUERY_NETWORK_INTERFACE_INFO response
        byte[] buffer = new byte[152];  // Fixed size structure
        
        // InterfaceIndex (4 bytes)
        writeInt4(buffer, 0, interfaceIndex);
        
        // Capability (4 bytes)
        writeInt4(buffer, 4, capability);
        
        // Reserved (4 bytes)
        writeInt4(buffer, 8, 0);
        
        // LinkSpeed (8 bytes)
        writeInt8(buffer, 12, linkSpeed * 1000000L);  // Convert to bps
        
        // SockaddrStorage (128 bytes)
        encodeSockaddr(buffer, 20);
        
        return buffer;
    }
    
    private void encodeSockaddr(byte[] buffer, int offset) {
        if (ipv6) {
            // IPv6 sockaddr_in6 structure
            writeInt2(buffer, offset, 23);  // AF_INET6
            writeInt2(buffer, offset + 2, 445);  // Port
            writeInt4(buffer, offset + 4, 0);  // Flow info
            System.arraycopy(address.getAddress(), 0, buffer, offset + 8, 16);
            writeInt4(buffer, offset + 24, 0);  // Scope ID
        } else {
            // IPv4 sockaddr_in structure
            writeInt2(buffer, offset, 2);  // AF_INET
            writeInt2(buffer, offset + 2, 445);  // Port
            System.arraycopy(address.getAddress(), 0, buffer, offset + 4, 4);
        }
    }
}
```

### 4.2 Channel Information
```java
package jcifs.internal.smb2.multichannel;

import jcifs.smb.SmbTransport;
import java.util.concurrent.atomic.AtomicLong;

public class ChannelInfo {
    private final String channelId;
    private final SmbTransport transport;
    private final NetworkInterfaceInfo localInterface;
    private final NetworkInterfaceInfo remoteInterface;
    private volatile ChannelState state;
    private final long establishedTime;
    private volatile long lastActivityTime;
    
    // Performance metrics
    private final AtomicLong bytesSent;
    private final AtomicLong bytesReceived;
    private final AtomicLong requestsSent;
    private final AtomicLong requestsReceived;
    private final AtomicLong errors;
    
    // Channel binding
    private byte[] bindingHash;
    private boolean isPrimary;
    
    public ChannelInfo(String id, SmbTransport transport, 
                      NetworkInterfaceInfo local, NetworkInterfaceInfo remote) {
        this.channelId = id;
        this.transport = transport;
        this.localInterface = local;
        this.remoteInterface = remote;
        this.state = ChannelState.DISCONNECTED;
        this.establishedTime = System.currentTimeMillis();
        this.lastActivityTime = establishedTime;
        
        this.bytesSent = new AtomicLong();
        this.bytesReceived = new AtomicLong();
        this.requestsSent = new AtomicLong();
        this.requestsReceived = new AtomicLong();
        this.errors = new AtomicLong();
        
        this.isPrimary = false;
    }
    
    public void updateActivity() {
        this.lastActivityTime = System.currentTimeMillis();
    }
    
    public long getIdleTime() {
        return System.currentTimeMillis() - lastActivityTime;
    }
    
    public boolean isHealthy() {
        return state == ChannelState.ACTIVE || state == ChannelState.ESTABLISHED;
    }
    
    public double getErrorRate() {
        long total = requestsSent.get();
        if (total == 0) return 0.0;
        return (double) errors.get() / total;
    }
    
    public long getThroughput() {
        long duration = System.currentTimeMillis() - establishedTime;
        if (duration == 0) return 0;
        return (bytesSent.get() + bytesReceived.get()) * 1000 / duration;
    }
    
    public int getScore() {
        // Calculate channel score for load balancing
        int score = 100;
        
        // Adjust based on state
        if (state == ChannelState.ACTIVE) score -= 20;  // Busy channel
        if (state != ChannelState.ESTABLISHED && state != ChannelState.ACTIVE) return 0;
        
        // Adjust based on error rate
        double errorRate = getErrorRate();
        if (errorRate > 0.1) score -= 50;
        else if (errorRate > 0.01) score -= 20;
        
        // Adjust based on interface capabilities
        score += localInterface.getScore() / 100;
        score += remoteInterface.getScore() / 100;
        
        // Prefer primary channel slightly
        if (isPrimary) score += 10;
        
        return Math.max(0, score);
    }
}
```

### 4.3 Channel Manager
```java
package jcifs.internal.smb2.multichannel;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class ChannelManager {
    private final CIFSContext context;
    private final SmbSession session;
    private final Map<String, ChannelInfo> channels;
    private final List<NetworkInterfaceInfo> localInterfaces;
    private final List<NetworkInterfaceInfo> remoteInterfaces;
    private final ScheduledExecutorService scheduler;
    private final ChannelLoadBalancer loadBalancer;
    private final ChannelFailover failover;
    
    private volatile boolean multiChannelEnabled;
    private final int maxChannels;
    private final AtomicInteger channelCounter;
    
    public ChannelManager(CIFSContext context, SmbSession session) {
        this.context = context;
        this.session = session;
        this.channels = new ConcurrentHashMap<>();
        this.localInterfaces = new ArrayList<>();
        this.remoteInterfaces = new ArrayList<>();
        this.scheduler = Executors.newScheduledThreadPool(2);
        this.loadBalancer = new ChannelLoadBalancer(this);
        this.failover = new ChannelFailover(this);
        
        Configuration config = context.getConfig();
        this.maxChannels = config.getMaxChannels();
        this.channelCounter = new AtomicInteger(0);
        this.multiChannelEnabled = false;
        
        // Schedule periodic health checks
        scheduler.scheduleAtFixedRate(this::performHealthCheck, 10, 10, TimeUnit.SECONDS);
        
        // Schedule interface discovery
        scheduler.scheduleAtFixedRate(this::discoverInterfaces, 0, 30, TimeUnit.SECONDS);
    }
    
    public void initializeMultiChannel() throws IOException {
        // Check server capability
        if (!session.getServer().supportsMultiChannel()) {
            log.info("Server does not support multi-channel");
            return;
        }
        
        // Query network interfaces from server
        queryRemoteInterfaces();
        
        // Discover local interfaces
        discoverLocalInterfaces();
        
        // Enable multi-channel if we have multiple usable interfaces
        if (canEnableMultiChannel()) {
            multiChannelEnabled = true;
            establishAdditionalChannels();
        }
    }
    
    private void queryRemoteInterfaces() throws IOException {
        // Send FSCTL_QUERY_NETWORK_INTERFACE_INFO
        Smb2IoctlRequest request = new Smb2IoctlRequest();
        request.setCtlCode(FSCTL_QUERY_NETWORK_INTERFACE_INFO);
        request.setFileId(new byte[16]);  // Use session ID
        request.setMaxOutputResponse(65536);
        
        Smb2IoctlResponse response = (Smb2IoctlResponse) session.send(request);
        
        if (response.isSuccess()) {
            parseNetworkInterfaces(response.getOutputData());
        }
    }
    
    private void parseNetworkInterfaces(byte[] data) {
        remoteInterfaces.clear();
        int offset = 0;
        
        while (offset < data.length) {
            // Parse NETWORK_INTERFACE_INFO structure
            int next = readInt4(data, offset);
            int ifIndex = readInt4(data, offset + 4);
            int capability = readInt4(data, offset + 8);
            long linkSpeed = readInt8(data, offset + 16);
            
            // Parse socket address
            InetAddress addr = parseSockaddr(data, offset + 24);
            
            NetworkInterfaceInfo info = new NetworkInterfaceInfo(
                addr, (int)(linkSpeed / 1000000));
            info.setInterfaceIndex(ifIndex);
            info.setCapability(capability);
            
            if (info.isUsableForChannel()) {
                remoteInterfaces.add(info);
            }
            
            if (next == 0) break;
            offset += next;
        }
        
        // Sort by score (best interfaces first)
        remoteInterfaces.sort((a, b) -> Integer.compare(b.getScore(), a.getScore()));
    }
    
    private void discoverLocalInterfaces() {
        localInterfaces.clear();
        
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            
            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                
                if (!ni.isUp() || ni.isLoopback() || ni.isVirtual()) {
                    continue;
                }
                
                Enumeration<InetAddress> addresses = ni.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    
                    // Estimate link speed (would need platform-specific code for actual speed)
                    int linkSpeed = ni.isVirtual() ? 100 : 1000;  // Default 1Gbps
                    
                    NetworkInterfaceInfo info = new NetworkInterfaceInfo(addr, linkSpeed);
                    if (info.isUsableForChannel()) {
                        localInterfaces.add(info);
                    }
                }
            }
        } catch (Exception e) {
            log.error("Failed to discover local interfaces", e);
        }
        
        // Sort by score
        localInterfaces.sort((a, b) -> Integer.compare(b.getScore(), a.getScore()));
    }
    
    private boolean canEnableMultiChannel() {
        return localInterfaces.size() > 0 && remoteInterfaces.size() > 0
            && (localInterfaces.size() > 1 || remoteInterfaces.size() > 1);
    }
    
    private void establishAdditionalChannels() {
        int currentChannels = channels.size();
        int targetChannels = Math.min(maxChannels, 
            Math.min(localInterfaces.size(), remoteInterfaces.size()));
        
        for (int i = currentChannels; i < targetChannels; i++) {
            try {
                establishChannel(i);
            } catch (Exception e) {
                log.warn("Failed to establish channel {}", i, e);
            }
        }
    }
    
    private void establishChannel(int index) throws IOException {
        // Select interfaces for this channel
        NetworkInterfaceInfo localIf = selectLocalInterface(index);
        NetworkInterfaceInfo remoteIf = selectRemoteInterface(index);
        
        // Create transport for this channel
        SmbTransport transport = createTransport(localIf, remoteIf);
        
        // Create channel info
        String channelId = "channel-" + channelCounter.incrementAndGet();
        ChannelInfo channel = new ChannelInfo(channelId, transport, localIf, remoteIf);
        
        // Establish connection
        channel.setState(ChannelState.CONNECTING);
        transport.connect();
        
        // Perform channel binding
        performChannelBinding(channel);
        
        // Add to active channels
        channels.put(channelId, channel);
        channel.setState(ChannelState.ESTABLISHED);
        
        log.info("Established channel {} using {}:{} -> {}:{}", 
            channelId, localIf.getAddress(), remoteIf.getAddress());
    }
    
    private void performChannelBinding(ChannelInfo channel) throws IOException {
        // Calculate channel binding hash
        byte[] bindingInfo = calculateBindingInfo(channel);
        byte[] bindingHash = calculateBindingHash(bindingInfo);
        channel.setBindingHash(bindingHash);
        
        // Send session setup with channel binding
        Smb2SessionSetupRequest request = new Smb2SessionSetupRequest();
        request.setSessionId(session.getSessionId());
        request.setFlags(SMB2_SESSION_FLAG_BINDING);
        request.setSecurityBuffer(bindingHash);
        
        Smb2SessionSetupResponse response = (Smb2SessionSetupResponse) 
            channel.getTransport().send(request);
        
        if (!response.isSuccess()) {
            throw new IOException("Channel binding failed: " + response.getStatus());
        }
    }
    
    private byte[] calculateBindingInfo(ChannelInfo channel) {
        // Combine session key with channel-specific data
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        try {
            baos.write(session.getSessionKey());
            baos.write(channel.getLocalInterface().getAddress().getAddress());
            baos.write(channel.getRemoteInterface().getAddress().getAddress());
            baos.write(ByteBuffer.allocate(8).putLong(System.currentTimeMillis()).array());
        } catch (IOException e) {
            // Should not happen with ByteArrayOutputStream
        }
        
        return baos.toByteArray();
    }
    
    private byte[] calculateBindingHash(byte[] bindingInfo) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(bindingInfo);
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 not available", e);
        }
    }
    
    public ChannelInfo selectChannel(SMBMessage message) {
        return loadBalancer.selectChannel(message);
    }
    
    public void handleChannelFailure(ChannelInfo channel, Exception error) {
        failover.handleFailure(channel, error);
    }
    
    private void performHealthCheck() {
        for (ChannelInfo channel : channels.values()) {
            if (channel.getIdleTime() > 60000) {  // 1 minute idle
                // Send keep-alive
                try {
                    sendKeepAlive(channel);
                } catch (Exception e) {
                    log.debug("Keep-alive failed for channel {}", channel.getChannelId());
                    handleChannelFailure(channel, e);
                }
            }
            
            // Check error rate
            if (channel.getErrorRate() > 0.1) {
                log.warn("High error rate on channel {}: {}", 
                    channel.getChannelId(), channel.getErrorRate());
                // Consider removing channel
            }
        }
    }
    
    private void discoverInterfaces() {
        if (!multiChannelEnabled) return;
        
        // Periodically rediscover interfaces in case of network changes
        discoverLocalInterfaces();
        
        try {
            queryRemoteInterfaces();
        } catch (Exception e) {
            log.debug("Failed to query remote interfaces", e);
        }
        
        // Check if we should add/remove channels
        adjustChannelCount();
    }
    
    private void adjustChannelCount() {
        int currentChannels = channels.size();
        int targetChannels = Math.min(maxChannels, 
            Math.min(localInterfaces.size(), remoteInterfaces.size()));
        
        if (currentChannels < targetChannels) {
            // Add more channels
            establishAdditionalChannels();
        } else if (currentChannels > targetChannels) {
            // Remove excess channels
            removeExcessChannels(currentChannels - targetChannels);
        }
    }
    
    public void shutdown() {
        scheduler.shutdown();
        
        for (ChannelInfo channel : channels.values()) {
            try {
                channel.getTransport().disconnect();
            } catch (Exception e) {
                log.debug("Error closing channel", e);
            }
        }
        
        channels.clear();
    }
}
```

### 4.4 Channel Load Balancer
```java
package jcifs.internal.smb2.multichannel;

import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

public class ChannelLoadBalancer {
    private final ChannelManager manager;
    private LoadBalancingStrategy strategy;
    
    public enum LoadBalancingStrategy {
        ROUND_ROBIN,      // Rotate through channels
        LEAST_LOADED,     // Select least busy channel
        WEIGHTED_RANDOM,  // Random selection weighted by score
        AFFINITY_BASED,   // Stick to same channel for related operations
        ADAPTIVE         // Dynamically adjust based on performance
    }
    
    public ChannelLoadBalancer(ChannelManager manager) {
        this.manager = manager;
        this.strategy = LoadBalancingStrategy.ADAPTIVE;
    }
    
    public ChannelInfo selectChannel(SMBMessage message) {
        Collection<ChannelInfo> availableChannels = manager.getHealthyChannels();
        
        if (availableChannels.isEmpty()) {
            throw new NoAvailableChannelException("No healthy channels available");
        }
        
        if (availableChannels.size() == 1) {
            return availableChannels.iterator().next();
        }
        
        switch (strategy) {
            case ROUND_ROBIN:
                return selectRoundRobin(availableChannels);
                
            case LEAST_LOADED:
                return selectLeastLoaded(availableChannels);
                
            case WEIGHTED_RANDOM:
                return selectWeightedRandom(availableChannels);
                
            case AFFINITY_BASED:
                return selectWithAffinity(message, availableChannels);
                
            case ADAPTIVE:
            default:
                return selectAdaptive(message, availableChannels);
        }
    }
    
    private ChannelInfo selectLeastLoaded(Collection<ChannelInfo> channels) {
        return channels.stream()
            .min(Comparator.comparingLong(ChannelInfo::getRequestsPending))
            .orElseThrow();
    }
    
    private ChannelInfo selectWeightedRandom(Collection<ChannelInfo> channels) {
        // Calculate total weight
        int totalWeight = channels.stream()
            .mapToInt(ChannelInfo::getScore)
            .sum();
        
        if (totalWeight == 0) {
            // All channels have zero score, pick randomly
            List<ChannelInfo> list = new ArrayList<>(channels);
            return list.get(ThreadLocalRandom.current().nextInt(list.size()));
        }
        
        // Weighted random selection
        int random = ThreadLocalRandom.current().nextInt(totalWeight);
        int currentWeight = 0;
        
        for (ChannelInfo channel : channels) {
            currentWeight += channel.getScore();
            if (random < currentWeight) {
                return channel;
            }
        }
        
        // Should not reach here
        return channels.iterator().next();
    }
    
    private ChannelInfo selectWithAffinity(SMBMessage message, Collection<ChannelInfo> channels) {
        // Use file handle or tree ID for affinity
        long affinityKey = 0;
        
        if (message instanceof Smb2ReadRequest) {
            affinityKey = Arrays.hashCode(((Smb2ReadRequest)message).getFileId());
        } else if (message instanceof Smb2WriteRequest) {
            affinityKey = Arrays.hashCode(((Smb2WriteRequest)message).getFileId());
        }
        
        if (affinityKey != 0) {
            // Select channel based on affinity key
            List<ChannelInfo> list = new ArrayList<>(channels);
            int index = Math.abs((int)(affinityKey % list.size()));
            return list.get(index);
        }
        
        // No affinity, use weighted random
        return selectWeightedRandom(channels);
    }
    
    private ChannelInfo selectAdaptive(SMBMessage message, Collection<ChannelInfo> channels) {
        // Adaptive strategy based on message type and size
        
        if (isLargeTransfer(message)) {
            // For large transfers, prefer high-bandwidth channels
            return channels.stream()
                .max(Comparator.comparingInt(c -> c.getRemoteInterface().getLinkSpeed()))
                .orElseThrow();
        }
        
        if (isMetadataOperation(message)) {
            // For metadata operations, prefer low-latency channels
            return selectLeastLoaded(channels);
        }
        
        // Default to weighted random for general operations
        return selectWeightedRandom(channels);
    }
    
    private boolean isLargeTransfer(SMBMessage message) {
        if (message instanceof Smb2ReadRequest) {
            return ((Smb2ReadRequest)message).getLength() > 1048576;  // 1MB
        }
        if (message instanceof Smb2WriteRequest) {
            return ((Smb2WriteRequest)message).getLength() > 1048576;
        }
        return false;
    }
    
    private boolean isMetadataOperation(SMBMessage message) {
        return message instanceof Smb2QueryInfoRequest
            || message instanceof Smb2SetInfoRequest
            || message instanceof Smb2QueryDirectoryRequest;
    }
}
```

### 4.5 Channel Failover Handler
```java
package jcifs.internal.smb2.multichannel;

import java.util.concurrent.*;

public class ChannelFailover {
    private final ChannelManager manager;
    private final ExecutorService executor;
    private final Map<String, FailoverState> failoverStates;
    
    public ChannelFailover(ChannelManager manager) {
        this.manager = manager;
        this.executor = Executors.newCachedThreadPool();
        this.failoverStates = new ConcurrentHashMap<>();
    }
    
    public static class FailoverState {
        private final String channelId;
        private final long failureTime;
        private int retryCount;
        private long nextRetryTime;
        
        public FailoverState(String channelId) {
            this.channelId = channelId;
            this.failureTime = System.currentTimeMillis();
            this.retryCount = 0;
            this.nextRetryTime = failureTime + 1000;  // Initial 1 second delay
        }
        
        public boolean shouldRetry() {
            return retryCount < 3 && System.currentTimeMillis() >= nextRetryTime;
        }
        
        public void incrementRetry() {
            retryCount++;
            // Exponential backoff: 1s, 2s, 4s
            nextRetryTime = System.currentTimeMillis() + (1000L << retryCount);
        }
    }
    
    public void handleFailure(ChannelInfo failedChannel, Exception error) {
        log.warn("Channel {} failed: {}", failedChannel.getChannelId(), error.getMessage());
        
        // Mark channel as failed
        failedChannel.setState(ChannelState.FAILED);
        
        // Get or create failover state
        FailoverState state = failoverStates.computeIfAbsent(
            failedChannel.getChannelId(), 
            FailoverState::new
        );
        
        // Redistribute pending operations
        redistributePendingOperations(failedChannel);
        
        // Attempt recovery
        if (state.shouldRetry()) {
            scheduleRecovery(failedChannel, state);
        } else {
            // Remove channel after max retries
            removeChannel(failedChannel);
        }
    }
    
    private void redistributePendingOperations(ChannelInfo failedChannel) {
        // Get pending operations from failed channel
        List<SMBMessage> pendingOps = failedChannel.getPendingOperations();
        
        if (pendingOps.isEmpty()) {
            return;
        }
        
        log.info("Redistributing {} pending operations from failed channel", 
            pendingOps.size());
        
        // Redistribute to healthy channels
        for (SMBMessage op : pendingOps) {
            try {
                ChannelInfo alternativeChannel = manager.selectChannel(op);
                alternativeChannel.getTransport().send(op);
            } catch (Exception e) {
                log.error("Failed to redistribute operation", e);
                // Notify waiting threads of failure
                op.notifyError(e);
            }
        }
    }
    
    private void scheduleRecovery(ChannelInfo channel, FailoverState state) {
        state.incrementRetry();
        
        executor.submit(() -> {
            try {
                log.info("Attempting to recover channel {}", channel.getChannelId());
                
                // Disconnect existing transport
                channel.getTransport().disconnect();
                
                // Create new transport
                SmbTransport newTransport = manager.createTransport(
                    channel.getLocalInterface(),
                    channel.getRemoteInterface()
                );
                
                // Reconnect
                channel.setState(ChannelState.CONNECTING);
                newTransport.connect();
                
                // Re-establish channel binding
                manager.performChannelBinding(channel);
                
                // Update channel with new transport
                channel.setTransport(newTransport);
                channel.setState(ChannelState.ESTABLISHED);
                
                // Clear failover state on success
                failoverStates.remove(channel.getChannelId());
                
                log.info("Successfully recovered channel {}", channel.getChannelId());
                
            } catch (Exception e) {
                log.warn("Failed to recover channel {}: {}", 
                    channel.getChannelId(), e.getMessage());
                
                // Schedule next retry or remove
                handleFailure(channel, e);
            }
        });
    }
    
    private void removeChannel(ChannelInfo channel) {
        log.info("Removing failed channel {} after max retries", channel.getChannelId());
        
        manager.removeChannel(channel);
        failoverStates.remove(channel.getChannelId());
        
        // Try to establish a replacement channel
        manager.establishReplacementChannel();
    }
}
```

## 5. Integration with Existing Code

### 5.1 Session Integration
```java
// In SmbSession.java
private ChannelManager channelManager;
private boolean multiChannelSupported;

public void negotiateMultiChannel() throws IOException {
    // Check if both client and server support multi-channel
    if (!context.getConfig().isUseMultiChannel()) {
        return;
    }
    
    if (!serverCapabilities.contains(SMB2_GLOBAL_CAP_MULTI_CHANNEL)) {
        log.debug("Server does not support multi-channel");
        return;
    }
    
    multiChannelSupported = true;
    
    // Initialize channel manager
    channelManager = new ChannelManager(context, this);
    channelManager.initializeMultiChannel();
}

public SmbTransport selectTransport(SMBMessage message) {
    if (channelManager != null && channelManager.isMultiChannelEnabled()) {
        ChannelInfo channel = channelManager.selectChannel(message);
        return channel.getTransport();
    }
    
    // Fall back to single channel
    return this.transport;
}

@Override
public void send(SMBMessage message) throws IOException {
    SmbTransport selectedTransport = selectTransport(message);
    
    try {
        selectedTransport.send(message);
    } catch (IOException e) {
        if (channelManager != null) {
            // Handle channel failure
            ChannelInfo channel = channelManager.getChannelForTransport(selectedTransport);
            channelManager.handleChannelFailure(channel, e);
            
            // Retry on different channel
            SmbTransport alternativeTransport = selectTransport(message);
            alternativeTransport.send(message);
        } else {
            throw e;
        }
    }
}
```

### 5.2 Transport Pool Integration
```java
// In SmbTransportPool.java
public SmbTransport getMultiChannelTransport(SmbSession session, 
                                            NetworkInterfaceInfo localIf,
                                            NetworkInterfaceInfo remoteIf) {
    String key = localIf.getAddress() + ":" + remoteIf.getAddress();
    
    return transports.computeIfAbsent(key, k -> {
        try {
            SmbTransport transport = new SmbTransport(
                context,
                remoteIf.getAddress(),
                remoteIf.getPort(),
                localIf.getAddress()
            );
            
            transport.connect();
            return transport;
            
        } catch (IOException e) {
            throw new RuntimeException("Failed to create transport", e);
        }
    });
}
```

### 5.3 Read/Write Operations with Multi-Channel
```java
// In SmbFile.java
public void optimizedLargeRead(byte[] buffer, long offset, int length) throws IOException {
    if (!session.isMultiChannelEnabled() || length < 1048576) {  // 1MB threshold
        // Use single channel for small reads
        normalRead(buffer, offset, length);
        return;
    }
    
    // Split large read across multiple channels
    ChannelManager channelManager = session.getChannelManager();
    List<ChannelInfo> channels = channelManager.getHealthyChannels();
    int channelCount = Math.min(channels.size(), 4);  // Max 4 parallel reads
    
    int chunkSize = length / channelCount;
    List<CompletableFuture<Void>> futures = new ArrayList<>();
    
    for (int i = 0; i < channelCount; i++) {
        final int chunkOffset = i * chunkSize;
        final int chunkLength = (i == channelCount - 1) ? 
            length - chunkOffset : chunkSize;
        final ChannelInfo channel = channels.get(i);
        
        CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
            try {
                Smb2ReadRequest request = new Smb2ReadRequest();
                request.setFileId(this.fileId);
                request.setOffset(offset + chunkOffset);
                request.setLength(chunkLength);
                
                Smb2ReadResponse response = (Smb2ReadResponse) 
                    channel.getTransport().send(request);
                
                System.arraycopy(response.getData(), 0, buffer, 
                    chunkOffset, response.getDataLength());
                    
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        });
        
        futures.add(future);
    }
    
    // Wait for all reads to complete
    try {
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
            .get(30, TimeUnit.SECONDS);
    } catch (Exception e) {
        throw new IOException("Multi-channel read failed", e);
    }
}
```

## 6. Configuration

### 6.1 Configuration Properties
```java
// In PropertyConfiguration.java
public static final String USE_MULTI_CHANNEL = "jcifs.smb.client.useMultiChannel";
public static final String MAX_CHANNELS = "jcifs.smb.client.maxChannels";
public static final String CHANNEL_BINDING_POLICY = "jcifs.smb.client.channelBindingPolicy";
public static final String LOAD_BALANCING_STRATEGY = "jcifs.smb.client.loadBalancingStrategy";
public static final String CHANNEL_HEALTH_CHECK_INTERVAL = "jcifs.smb.client.channelHealthCheckInterval";

public boolean isUseMultiChannel() {
    return getBooleanProperty(USE_MULTI_CHANNEL, true);
}

public int getMaxChannels() {
    return getIntProperty(MAX_CHANNELS, 4);
}

public int getChannelBindingPolicy() {
    String policy = getProperty(CHANNEL_BINDING_POLICY, "preferred");
    switch (policy.toLowerCase()) {
        case "disabled": return 0;
        case "required": return 2;
        default: return 1;  // preferred
    }
}

public LoadBalancingStrategy getLoadBalancingStrategy() {
    String strategy = getProperty(LOAD_BALANCING_STRATEGY, "adaptive");
    return LoadBalancingStrategy.valueOf(strategy.toUpperCase());
}
```

## 7. Testing Strategy

### 7.1 Unit Tests
```java
@Test
public void testChannelSelection() {
    ChannelManager manager = new ChannelManager(context, session);
    
    // Add test channels
    ChannelInfo channel1 = createTestChannel("channel1", 1000);  // 1Gbps
    ChannelInfo channel2 = createTestChannel("channel2", 10000); // 10Gbps
    
    manager.addChannel(channel1);
    manager.addChannel(channel2);
    
    // Test load balancer selection
    ChannelLoadBalancer balancer = new ChannelLoadBalancer(manager);
    
    // Large transfer should prefer high-bandwidth channel
    Smb2ReadRequest largeRead = new Smb2ReadRequest();
    largeRead.setLength(10485760);  // 10MB
    
    ChannelInfo selected = balancer.selectChannel(largeRead);
    assertEquals(channel2, selected);  // Should select 10Gbps channel
}

@Test
public void testChannelFailover() throws Exception {
    ChannelManager manager = new ChannelManager(context, session);
    ChannelFailover failover = new ChannelFailover(manager);
    
    ChannelInfo channel = createTestChannel("test-channel", 1000);
    manager.addChannel(channel);
    
    // Simulate failure
    IOException error = new IOException("Network error");
    failover.handleFailure(channel, error);
    
    // Verify channel marked as failed
    assertEquals(ChannelState.FAILED, channel.getState());
    
    // Verify recovery attempted
    Thread.sleep(2000);
    assertTrue(channel.getState() == ChannelState.ESTABLISHED 
        || manager.getChannels().isEmpty());
}
```

### 7.2 Integration Tests
```java
@Test
public void testMultiChannelThroughput() throws Exception {
    // Requires multi-NIC test environment
    CIFSContext context = getTestContext();
    context.getConfig().setProperty("jcifs.smb.client.useMultiChannel", "true");
    context.getConfig().setProperty("jcifs.smb.client.maxChannels", "4");
    
    SmbFile file = new SmbFile("smb://server/share/largefile.dat", context);
    
    // Measure single channel throughput
    long singleChannelTime = measureReadTime(file, false);
    
    // Measure multi-channel throughput
    long multiChannelTime = measureReadTime(file, true);
    
    // Multi-channel should be faster
    assertTrue(multiChannelTime < singleChannelTime * 0.7);  // At least 30% improvement
}
```

## 8. Performance Metrics

### 8.1 Channel Statistics
```java
public class MultiChannelStatistics {
    private final Map<String, ChannelStatistics> channelStats;
    
    public class ChannelStatistics {
        private final AtomicLong bytesSent = new AtomicLong();
        private final AtomicLong bytesReceived = new AtomicLong();
        private final AtomicLong operations = new AtomicLong();
        private final AtomicLong errors = new AtomicLong();
        private final AtomicLong latencyTotal = new AtomicLong();
        
        public double getAverageLatency() {
            long ops = operations.get();
            if (ops == 0) return 0;
            return (double) latencyTotal.get() / ops;
        }
        
        public long getThroughput() {
            return bytesSent.get() + bytesReceived.get();
        }
    }
    
    public void recordOperation(String channelId, long bytes, long latency, boolean success) {
        ChannelStatistics stats = channelStats.computeIfAbsent(channelId, 
            k -> new ChannelStatistics());
            
        stats.operations.incrementAndGet();
        stats.latencyTotal.addAndGet(latency);
        
        if (success) {
            stats.bytesReceived.addAndGet(bytes);
        } else {
            stats.errors.incrementAndGet();
        }
    }
    
    public double getAggregatedThroughput() {
        return channelStats.values().stream()
            .mapToLong(ChannelStatistics::getThroughput)
            .sum();
    }
}
```

## 9. Security Considerations

### 9.1 Channel Binding Security
```java
public class SecureChannelBinding {
    private final byte[] sessionKey;
    
    public byte[] generateChannelBindingHash(ChannelInfo channel) throws GeneralSecurityException {
        // Use HMAC-SHA256 for channel binding
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(sessionKey, "HmacSHA256");
        mac.init(keySpec);
        
        // Include channel-specific data
        mac.update(channel.getLocalInterface().getAddress().getAddress());
        mac.update(channel.getRemoteInterface().getAddress().getAddress());
        mac.update(ByteBuffer.allocate(8)
            .putLong(channel.getEstablishedTime()).array());
        
        return mac.doFinal();
    }
}
```