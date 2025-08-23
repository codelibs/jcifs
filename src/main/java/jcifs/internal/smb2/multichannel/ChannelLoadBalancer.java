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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;

import jcifs.internal.CommonServerMessageBlock;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.info.Smb2QueryDirectoryRequest;
import jcifs.internal.smb2.info.Smb2QueryInfoRequest;
import jcifs.internal.smb2.info.Smb2SetInfoRequest;
import jcifs.internal.smb2.io.Smb2ReadRequest;
import jcifs.internal.smb2.io.Smb2WriteRequest;

/**
 * Load balancer for SMB3 Multi-Channel connections
 */
public class ChannelLoadBalancer {

    private final ChannelManager manager;
    private LoadBalancingStrategy strategy;
    private final AtomicInteger roundRobinCounter;

    /**
     * Create channel load balancer
     *
     * @param manager channel manager
     */
    public ChannelLoadBalancer(ChannelManager manager) {
        this.manager = manager;
        this.strategy = LoadBalancingStrategy.ADAPTIVE;
        this.roundRobinCounter = new AtomicInteger(0);
    }

    /**
     * Get current load balancing strategy
     *
     * @return current strategy
     */
    public LoadBalancingStrategy getStrategy() {
        return strategy;
    }

    /**
     * Set load balancing strategy
     *
     * @param strategy new strategy
     */
    public void setStrategy(LoadBalancingStrategy strategy) {
        this.strategy = strategy;
    }

    /**
     * Select a channel for the given message
     *
     * @param message SMB message to send
     * @return selected channel
     * @throws NoAvailableChannelException if no healthy channels available
     */
    public ChannelInfo selectChannel(CommonServerMessageBlock message) throws NoAvailableChannelException {
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

    private ChannelInfo selectRoundRobin(Collection<ChannelInfo> channels) {
        List<ChannelInfo> list = new ArrayList<>(channels);
        int index = Math.abs(roundRobinCounter.getAndIncrement() % list.size());
        return list.get(index);
    }

    private ChannelInfo selectLeastLoaded(Collection<ChannelInfo> channels) {
        return channels.stream().min(Comparator.comparingLong(ChannelInfo::getRequestsPending)).orElseThrow();
    }

    private ChannelInfo selectWeightedRandom(Collection<ChannelInfo> channels) {
        // Calculate total weight
        int totalWeight = channels.stream().mapToInt(ChannelInfo::getScore).sum();

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

    private ChannelInfo selectWithAffinity(CommonServerMessageBlock message, Collection<ChannelInfo> channels) {
        // Use file handle or tree ID for affinity
        long affinityKey = 0;

        // Use tree ID for SMB2 requests for affinity
        if (message instanceof ServerMessageBlock2Request) {
            ServerMessageBlock2Request smb2Request = (ServerMessageBlock2Request) message;
            affinityKey = smb2Request.getTreeId();
        }

        if (affinityKey != 0) {
            // Select channel based on affinity key
            List<ChannelInfo> list = new ArrayList<>(channels);
            int index = Math.abs((int) (affinityKey % list.size()));
            return list.get(index);
        }

        // No affinity, use weighted random
        return selectWeightedRandom(channels);
    }

    private ChannelInfo selectAdaptive(CommonServerMessageBlock message, Collection<ChannelInfo> channels) {
        // Adaptive strategy based on message type and size

        if (isLargeTransfer(message)) {
            // For large transfers, prefer high-bandwidth channels
            return channels.stream().max(Comparator.comparingInt(c -> c.getRemoteInterface().getLinkSpeed())).orElseThrow();
        }

        if (isMetadataOperation(message)) {
            // For metadata operations, prefer low-latency channels
            return selectLeastLoaded(channels);
        }

        // Default to weighted random for general operations
        return selectWeightedRandom(channels);
    }

    private boolean isLargeTransfer(CommonServerMessageBlock message) {
        if (message instanceof Smb2ReadRequest) {
            return ((Smb2ReadRequest) message).getReadLength() > 1048576; // 1MB
        }
        if (message instanceof Smb2WriteRequest) {
            // Data length not accessible, assume large writes for now
            return true;
        }
        return false;
    }

    private boolean isMetadataOperation(CommonServerMessageBlock message) {
        return message instanceof Smb2QueryInfoRequest || message instanceof Smb2SetInfoRequest
                || message instanceof Smb2QueryDirectoryRequest;
    }

    /**
     * Exception thrown when no healthy channels are available
     */
    public static class NoAvailableChannelException extends RuntimeException {

        private static final long serialVersionUID = 1L;

        /**
         * Create exception
         *
         * @param message error message
         */
        public NoAvailableChannelException(String message) {
            super(message);
        }

        /**
         * Create exception with cause
         *
         * @param message error message
         * @param cause underlying cause
         */
        public NoAvailableChannelException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
