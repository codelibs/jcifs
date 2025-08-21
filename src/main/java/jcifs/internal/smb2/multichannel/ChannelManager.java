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
package jcifs.internal.smb2.multichannel;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.SmbSession;
import jcifs.SmbTransport;

import jcifs.internal.CommonServerMessageBlock;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.smb2.ioctl.Smb2IoctlRequest;
import jcifs.internal.smb2.ioctl.Smb2IoctlResponse;
import jcifs.internal.smb2.ioctl.QueryNetworkInterfaceInfoResponse;
import jcifs.internal.smb2.session.Smb2SessionSetupRequest;
import jcifs.internal.smb2.session.Smb2SessionSetupResponse;

/**
 * Manages SMB3 Multi-Channel connections
 */
public class ChannelManager {

    private static final Logger log = LoggerFactory.getLogger(ChannelManager.class);

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

    /**
     * Create channel manager
     *
     * @param context CIFS context
     * @param session SMB session
     */
    public ChannelManager(CIFSContext context, SmbSession session) {
        this.context = context;
        this.session = session;
        this.channels = new ConcurrentHashMap<>();
        this.localInterfaces = new ArrayList<>();
        this.remoteInterfaces = new ArrayList<>();
        this.scheduler = Executors.newScheduledThreadPool(2, r -> {
            Thread t = new Thread(r, "MultiChannelScheduler");
            t.setDaemon(true);
            return t;
        });
        this.loadBalancer = new ChannelLoadBalancer(this);
        this.failover = new ChannelFailover(this);

        Configuration config = context.getConfig();
        this.maxChannels = getMaxChannelsFromConfig(config);
        this.channelCounter = new AtomicInteger(0);
        this.multiChannelEnabled = false;

        // Schedule periodic health checks
        scheduler.scheduleAtFixedRate(this::performHealthCheck, 10, 10, TimeUnit.SECONDS);

        // Schedule interface discovery
        scheduler.scheduleAtFixedRate(this::discoverInterfaces, 0, 30, TimeUnit.SECONDS);
    }

    /**
     * Initialize multi-channel support
     *
     * @throws IOException if initialization fails
     */
    public void initializeMultiChannel() throws IOException {
        // Check server capability
        if (!supportsMultiChannel()) {
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
            log.info("Multi-channel enabled with {} channels", channels.size());
        }
    }

    /**
     * Check if multi-channel is enabled
     *
     * @return true if enabled
     */
    public boolean isUseMultiChannel() {
        return multiChannelEnabled;
    }

    /**
     * Get the load balancer
     *
     * @return load balancer instance
     */
    public ChannelLoadBalancer getLoadBalancer() {
        return loadBalancer;
    }

    /**
     * Get all channels
     *
     * @return collection of all channels
     */
    public Collection<ChannelInfo> getChannels() {
        return channels.values();
    }

    /**
     * Get healthy channels only
     *
     * @return collection of healthy channels
     */
    public Collection<ChannelInfo> getHealthyChannels() {
        return channels.values()
                .stream()
                .filter(ChannelInfo::isHealthy)
                .collect(ArrayList::new, (list, item) -> list.add(item), (list1, list2) -> list1.addAll(list2));
    }

    /**
     * Select a channel for the given message
     *
     * @param message message to send
     * @return selected channel
     */
    public ChannelInfo selectChannel(CommonServerMessageBlock message) {
        return loadBalancer.selectChannel(message);
    }

    /**
     * Handle channel failure
     *
     * @param channel failed channel
     * @param error error that caused failure
     */
    public void handleChannelFailure(ChannelInfo channel, Exception error) {
        failover.handleFailure(channel, error);
    }

    /**
     * Get channel for specific transport
     *
     * @param transport transport instance
     * @return corresponding channel or null
     */
    public ChannelInfo getChannelForTransport(SmbTransport transport) {
        return channels.values().stream().filter(c -> c.getTransport() == transport).findFirst().orElse(null);
    }

    /**
     * Remove a channel
     *
     * @param channel channel to remove
     */
    public void removeChannel(ChannelInfo channel) {
        channels.remove(channel.getChannelId());
        try {
            if (channel.getTransport() != null) {
                channel.getTransport().close();
            }
        } catch (Exception e) {
            log.debug("Error disconnecting removed channel", e);
        }
    }

    /**
     * Establish a replacement channel
     */
    public void establishReplacementChannel() {
        if (!multiChannelEnabled)
            return;

        try {
            int currentChannels = channels.size();
            if (currentChannels < maxChannels && canEstablishMoreChannels()) {
                establishChannel(currentChannels);
            }
        } catch (Exception e) {
            log.warn("Failed to establish replacement channel", e);
        }
    }

    /**
     * Create transport for given interfaces
     *
     * @param localInterface local interface
     * @param remoteInterface remote interface
     * @return created transport
     * @throws IOException if transport creation fails
     */
    public SmbTransport createTransport(NetworkInterfaceInfo localInterface, NetworkInterfaceInfo remoteInterface) throws IOException {
        // This would need to be implemented based on the actual SmbTransport constructor
        // For now, return null - this needs integration with the actual transport creation
        throw new UnsupportedOperationException("Transport creation needs integration with SmbTransportPool");
    }

    /**
     * Perform channel binding for a channel
     *
     * @param channel channel to bind
     * @throws IOException if binding fails
     */
    public void performChannelBinding(ChannelInfo channel) throws IOException {
        // Calculate channel binding hash
        byte[] bindingInfo = calculateBindingInfo(channel);
        byte[] bindingHash = calculateBindingHash(bindingInfo);
        channel.setBindingHash(bindingHash);

        // Send session setup with channel binding
        Smb2SessionSetupRequest request = new Smb2SessionSetupRequest(context, 0, 0, 0L, new byte[0]);
        request.setSessionId(getSessionId());
        request.setSessionBinding(true);

        // Channel binding would be handled through proper transport interface
        // For now, skip actual binding implementation

        // Binding success assumed for now
    }

    /**
     * Shutdown the channel manager
     */
    public void shutdown() {
        scheduler.shutdown();
        failover.shutdown();

        for (ChannelInfo channel : channels.values()) {
            try {
                channel.getTransport().close();
            } catch (Exception e) {
                log.debug("Error closing channel", e);
            }
        }

        channels.clear();
    }

    private boolean supportsMultiChannel() {
        // Check if both client and server support multi-channel
        if (!context.getConfig().isUseMultiChannel()) {
            return false;
        }

        // This would need to check server capabilities from negotiation
        // For now, assume server supports it if client enables it
        return true;
    }

    private void queryRemoteInterfaces() throws IOException {
        // Send FSCTL_QUERY_NETWORK_INTERFACE_INFO
        Smb2IoctlRequest request =
                new Smb2IoctlRequest(context.getConfig(), Smb2IoctlRequest.FSCTL_QUERY_NETWORK_INTERFACE_INFO, new byte[16] // Use session ID as file ID
                );
        request.setMaxOutputResponse(65536);
        request.setFlags(Smb2IoctlRequest.SMB2_O_IOCTL_IS_FSCTL);

        // Network interface discovery would use proper session interface
        // For now, skip actual IOCTL implementation

        // Interface parsing would happen here
    }

    private void parseNetworkInterfaces(byte[] data) {
        remoteInterfaces.clear();

        if (data == null || data.length == 0) {
            return;
        }

        QueryNetworkInterfaceInfoResponse response = new QueryNetworkInterfaceInfoResponse();
        response.decode(data, 0, data.length);

        for (NetworkInterfaceInfo info : response.getInterfaces()) {
            if (info.isUsableForChannel()) {
                remoteInterfaces.add(info);
            }
        }

        // Sort by score (best interfaces first)
        remoteInterfaces.sort((a, b) -> Integer.compare(b.getScore(), a.getScore()));

        log.debug("Discovered {} remote network interfaces", remoteInterfaces.size());
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
                    int linkSpeed = ni.isVirtual() ? 100 : 1000; // Default 1Gbps

                    NetworkInterfaceInfo info = new NetworkInterfaceInfo(addr, linkSpeed);
                    if (info.isUsableForChannel()) {
                        localInterfaces.add(info);
                    }
                }
            }
        } catch (SocketException e) {
            log.error("Failed to discover local interfaces", e);
        }

        // Sort by score
        localInterfaces.sort((a, b) -> Integer.compare(b.getScore(), a.getScore()));

        log.debug("Discovered {} local network interfaces", localInterfaces.size());
    }

    private boolean canEnableMultiChannel() {
        return localInterfaces.size() > 0 && remoteInterfaces.size() > 0 && (localInterfaces.size() > 1 || remoteInterfaces.size() > 1);
    }

    private void establishAdditionalChannels() {
        int currentChannels = channels.size();
        int targetChannels = Math.min(maxChannels, Math.min(localInterfaces.size(), remoteInterfaces.size()));

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

        if (localIf == null || remoteIf == null) {
            log.warn("Cannot select interfaces for channel {}", index);
            return;
        }

        // Create transport for this channel
        SmbTransport transport = createTransport(localIf, remoteIf);

        // Create channel info
        String channelId = "channel-" + channelCounter.incrementAndGet();
        ChannelInfo channel = new ChannelInfo(channelId, transport, localIf, remoteIf);

        // Establish connection
        channel.setState(ChannelState.CONNECTING);
        // Connection would be ensured through proper transport interface

        // Perform channel binding
        performChannelBinding(channel);

        // Add to active channels
        channels.put(channelId, channel);
        channel.setState(ChannelState.ESTABLISHED);

        log.info("Established channel {} using {}:{} -> {}:{}", channelId, localIf.getAddress(), remoteIf.getAddress());
    }

    private NetworkInterfaceInfo selectLocalInterface(int index) {
        if (localInterfaces.isEmpty())
            return null;
        return localInterfaces.get(index % localInterfaces.size());
    }

    private NetworkInterfaceInfo selectRemoteInterface(int index) {
        if (remoteInterfaces.isEmpty())
            return null;
        return remoteInterfaces.get(index % remoteInterfaces.size());
    }

    private boolean canEstablishMoreChannels() {
        return localInterfaces.size() > 0 && remoteInterfaces.size() > 0;
    }

    private byte[] calculateBindingInfo(ChannelInfo channel) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try {
            // Combine session key with channel-specific data
            byte[] sessionKey = getSessionKey();
            if (sessionKey != null) {
                baos.write(sessionKey);
            }
            baos.write(channel.getLocalInterface().getAddress().getAddress());
            baos.write(channel.getRemoteInterface().getAddress().getAddress());
            baos.write(ByteBuffer.allocate(8).putLong(System.currentTimeMillis()).array());
        } catch (IOException e) {
            // Should not happen with ByteArrayOutputStream
            log.error("Error creating binding info", e);
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

    private void performHealthCheck() {
        for (ChannelInfo channel : channels.values()) {
            if (channel.getIdleTime() > 60000) { // 1 minute idle
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
                log.warn("High error rate on channel {}: {}", channel.getChannelId(), channel.getErrorRate());
            }
        }
    }

    private void sendKeepAlive(ChannelInfo channel) throws IOException {
        // Send echo request as keep-alive
        // This would need to be implemented with actual echo request/response
        log.debug("Sending keep-alive for channel {}", channel.getChannelId());
        channel.updateActivity();
    }

    private void discoverInterfaces() {
        if (!multiChannelEnabled)
            return;

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
        int targetChannels = Math.min(maxChannels, Math.min(localInterfaces.size(), remoteInterfaces.size()));

        if (currentChannels < targetChannels) {
            // Add more channels
            establishAdditionalChannels();
        } else if (currentChannels > targetChannels) {
            // Remove excess channels
            removeExcessChannels(currentChannels - targetChannels);
        }
    }

    private void removeExcessChannels(int excessCount) {
        List<ChannelInfo> channelsToRemove = channels.values()
                .stream()
                .filter(c -> !c.isPrimary()) // Never remove primary channel
                .sorted(Comparator.comparingInt(ChannelInfo::getScore)) // Remove lowest scoring first
                .limit(excessCount)
                .collect(ArrayList::new, (list, item) -> list.add(item), (list1, list2) -> list1.addAll(list2));

        for (ChannelInfo channel : channelsToRemove) {
            removeChannel(channel);
            log.info("Removed excess channel {}", channel.getChannelId());
        }
    }

    private int getMaxChannelsFromConfig(Configuration config) {
        // This would read from configuration
        // For now, return default
        return Smb2ChannelCapabilities.DEFAULT_MAX_CHANNELS;
    }

    private long getSessionId() {
        // This would need to get the actual session ID from the SMB session
        return 0; // Placeholder
    }

    private byte[] getSessionKey() {
        // This would need to get the actual session key from the SMB session
        return new byte[16]; // Placeholder
    }
}
