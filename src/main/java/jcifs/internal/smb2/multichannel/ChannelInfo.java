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

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

import jcifs.SmbTransport;
import jcifs.internal.CommonServerMessageBlock;

/**
 * Information about a multi-channel connection
 */
public class ChannelInfo {

    private final String channelId;
    private volatile SmbTransport transport;
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

    // Pending operations
    private final List<CommonServerMessageBlock> pendingOperations;

    /**
     * Create channel information
     *
     * @param channelId unique channel identifier
     * @param transport SMB transport for this channel
     * @param localInterface local network interface
     * @param remoteInterface remote network interface
     */
    public ChannelInfo(String channelId, SmbTransport transport, NetworkInterfaceInfo localInterface,
            NetworkInterfaceInfo remoteInterface) {
        this.channelId = channelId;
        this.transport = transport;
        this.localInterface = localInterface;
        this.remoteInterface = remoteInterface;
        this.state = ChannelState.DISCONNECTED;
        this.establishedTime = System.currentTimeMillis();
        this.lastActivityTime = establishedTime;

        this.bytesSent = new AtomicLong();
        this.bytesReceived = new AtomicLong();
        this.requestsSent = new AtomicLong();
        this.requestsReceived = new AtomicLong();
        this.errors = new AtomicLong();

        this.isPrimary = false;
        this.pendingOperations = new CopyOnWriteArrayList<>();
    }

    /**
     * Get channel ID
     *
     * @return channel identifier
     */
    public String getChannelId() {
        return channelId;
    }

    /**
     * Get the transport for this channel
     *
     * @return SMB transport
     */
    public SmbTransport getTransport() {
        return transport;
    }

    /**
     * Set the transport for this channel
     *
     * @param transport SMB transport
     */
    public void setTransport(SmbTransport transport) {
        this.transport = transport;
    }

    /**
     * Get local network interface
     *
     * @return local interface info
     */
    public NetworkInterfaceInfo getLocalInterface() {
        return localInterface;
    }

    /**
     * Get remote network interface
     *
     * @return remote interface info
     */
    public NetworkInterfaceInfo getRemoteInterface() {
        return remoteInterface;
    }

    /**
     * Get current channel state
     *
     * @return channel state
     */
    public ChannelState getState() {
        return state;
    }

    /**
     * Set channel state
     *
     * @param state new state
     */
    public void setState(ChannelState state) {
        this.state = state;
    }

    /**
     * Get the time when channel was established
     *
     * @return establishment time in milliseconds
     */
    public long getEstablishedTime() {
        return establishedTime;
    }

    /**
     * Get the last activity time
     *
     * @return last activity time in milliseconds
     */
    public long getLastActivityTime() {
        return lastActivityTime;
    }

    /**
     * Update activity timestamp
     */
    public void updateActivity() {
        this.lastActivityTime = System.currentTimeMillis();
    }

    /**
     * Get idle time since last activity
     *
     * @return idle time in milliseconds
     */
    public long getIdleTime() {
        return System.currentTimeMillis() - lastActivityTime;
    }

    /**
     * Check if channel is in healthy state
     *
     * @return true if healthy
     */
    public boolean isHealthy() {
        return state == ChannelState.ACTIVE || state == ChannelState.ESTABLISHED;
    }

    /**
     * Get channel binding hash
     *
     * @return binding hash bytes
     */
    public byte[] getBindingHash() {
        return bindingHash;
    }

    /**
     * Set channel binding hash
     *
     * @param bindingHash binding hash bytes
     */
    public void setBindingHash(byte[] bindingHash) {
        this.bindingHash = bindingHash;
    }

    /**
     * Check if this is the primary channel
     *
     * @return true if primary
     */
    public boolean isPrimary() {
        return isPrimary;
    }

    /**
     * Set primary channel flag
     *
     * @param primary true if primary
     */
    public void setPrimary(boolean primary) {
        this.isPrimary = primary;
    }

    /**
     * Get number of bytes sent
     *
     * @return bytes sent
     */
    public long getBytesSent() {
        return bytesSent.get();
    }

    /**
     * Get number of bytes received
     *
     * @return bytes received
     */
    public long getBytesReceived() {
        return bytesReceived.get();
    }

    /**
     * Get number of requests sent
     *
     * @return requests sent
     */
    public long getRequestsSent() {
        return requestsSent.get();
    }

    /**
     * Get number of requests received
     *
     * @return requests received
     */
    public long getRequestsReceived() {
        return requestsReceived.get();
    }

    /**
     * Get number of errors
     *
     * @return error count
     */
    public long getErrors() {
        return errors.get();
    }

    /**
     * Add bytes sent
     *
     * @param bytes number of bytes
     */
    public void addBytesSent(long bytes) {
        bytesSent.addAndGet(bytes);
    }

    /**
     * Add bytes received
     *
     * @param bytes number of bytes
     */
    public void addBytesReceived(long bytes) {
        bytesReceived.addAndGet(bytes);
    }

    /**
     * Increment requests sent counter
     */
    public void incrementRequestsSent() {
        requestsSent.incrementAndGet();
    }

    /**
     * Increment requests received counter
     */
    public void incrementRequestsReceived() {
        requestsReceived.incrementAndGet();
    }

    /**
     * Increment error counter
     */
    public void incrementErrors() {
        errors.incrementAndGet();
    }

    /**
     * Get error rate (errors / total requests)
     *
     * @return error rate between 0.0 and 1.0
     */
    public double getErrorRate() {
        long total = requestsSent.get();
        if (total == 0)
            return 0.0;
        return (double) errors.get() / total;
    }

    /**
     * Get throughput in bytes per second
     *
     * @return throughput in bps
     */
    public long getThroughput() {
        long duration = System.currentTimeMillis() - establishedTime;
        if (duration == 0)
            return 0;
        return (bytesSent.get() + bytesReceived.get()) * 1000 / duration;
    }

    /**
     * Get number of pending operations
     *
     * @return number of pending operations
     */
    public long getRequestsPending() {
        return pendingOperations.size();
    }

    /**
     * Get pending operations list
     *
     * @return list of pending operations
     */
    public List<CommonServerMessageBlock> getPendingOperations() {
        return pendingOperations;
    }

    /**
     * Add a pending operation
     *
     * @param operation operation to add
     */
    public void addPendingOperation(CommonServerMessageBlock operation) {
        pendingOperations.add(operation);
    }

    /**
     * Remove a pending operation
     *
     * @param operation operation to remove
     * @return true if operation was removed
     */
    public boolean removePendingOperation(CommonServerMessageBlock operation) {
        return pendingOperations.remove(operation);
    }

    /**
     * Clear all pending operations
     */
    public void clearPendingOperations() {
        pendingOperations.clear();
    }

    /**
     * Calculate channel score for load balancing (higher is better)
     *
     * @return channel score
     */
    public int getScore() {
        int score = 100;

        // Adjust based on state
        if (state == ChannelState.ACTIVE)
            score -= 20; // Busy channel penalty
        if (state != ChannelState.ESTABLISHED && state != ChannelState.ACTIVE)
            return 0;

        // Adjust based on error rate
        double errorRate = getErrorRate();
        if (errorRate > 0.1)
            score -= 50;
        else if (errorRate > 0.01)
            score -= 20;

        // Adjust based on interface capabilities
        score += localInterface.getScore() / 100;
        score += remoteInterface.getScore() / 100;

        // Prefer primary channel slightly
        if (isPrimary)
            score += 10;

        // Penalize channels with many pending operations
        score -= (int) getRequestsPending();

        return Math.max(0, score);
    }

    @Override
    public String toString() {
        return "ChannelInfo{" + "channelId='" + channelId + '\'' + ", state=" + state + ", local=" + localInterface.getAddress()
                + ", remote=" + remoteInterface.getAddress() + ", throughput=" + getThroughput() + " bps" + ", pending="
                + getRequestsPending() + ", primary=" + isPrimary + '}';
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null || getClass() != obj.getClass())
            return false;
        ChannelInfo that = (ChannelInfo) obj;
        return channelId != null ? channelId.equals(that.channelId) : that.channelId == null;
    }

    @Override
    public int hashCode() {
        return channelId != null ? channelId.hashCode() : 0;
    }
}
