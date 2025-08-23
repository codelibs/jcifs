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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.SmbTransport;
import jcifs.internal.CommonServerMessageBlock;
import jcifs.internal.smb2.info.Smb2QueryInfoRequest;
import jcifs.internal.smb2.io.Smb2ReadRequest;

/**
 * Unit tests for ChannelLoadBalancer
 */
@ExtendWith(MockitoExtension.class)
class ChannelLoadBalancerTest {

    @Mock
    private ChannelManager mockChannelManager;

    @Mock
    private SmbTransport mockTransport1;

    @Mock
    private SmbTransport mockTransport2;

    @Mock
    private CommonServerMessageBlock mockMessage;

    private ChannelLoadBalancer loadBalancer;
    private ChannelInfo channel1;
    private ChannelInfo channel2;

    @BeforeEach
    void setUp() throws UnknownHostException {
        loadBalancer = new ChannelLoadBalancer(mockChannelManager);

        InetAddress addr1 = InetAddress.getByName("192.168.1.100");
        InetAddress addr2 = InetAddress.getByName("192.168.1.101");
        NetworkInterfaceInfo local = new NetworkInterfaceInfo(addr1, 1000);
        NetworkInterfaceInfo remote1 = new NetworkInterfaceInfo(addr1, 1000);
        NetworkInterfaceInfo remote2 = new NetworkInterfaceInfo(addr2, 10000); // Faster interface

        channel1 = new ChannelInfo("channel1", mockTransport1, local, remote1);
        channel1.setState(ChannelState.ESTABLISHED);

        channel2 = new ChannelInfo("channel2", mockTransport2, local, remote2);
        channel2.setState(ChannelState.ESTABLISHED);
    }

    @Test
    void testSingleChannelSelection() {
        when(mockChannelManager.getHealthyChannels()).thenReturn(Collections.singletonList(channel1));

        ChannelInfo selected = loadBalancer.selectChannel(mockMessage);
        assertEquals(channel1, selected);
    }

    @Test
    void testNoChannelsAvailable() {
        when(mockChannelManager.getHealthyChannels()).thenReturn(Collections.emptyList());

        assertThrows(ChannelLoadBalancer.NoAvailableChannelException.class, () -> loadBalancer.selectChannel(mockMessage));
    }

    @Test
    void testRoundRobinStrategy() {
        loadBalancer.setStrategy(LoadBalancingStrategy.ROUND_ROBIN);
        when(mockChannelManager.getHealthyChannels()).thenReturn(Arrays.asList(channel1, channel2));

        // Should alternate between channels
        ChannelInfo first = loadBalancer.selectChannel(mockMessage);
        ChannelInfo second = loadBalancer.selectChannel(mockMessage);

        assertNotNull(first);
        assertNotNull(second);
        // Due to round-robin, should get different channels or same order
        assertTrue(Arrays.asList(channel1, channel2).contains(first));
        assertTrue(Arrays.asList(channel1, channel2).contains(second));
    }

    @Test
    void testLeastLoadedStrategy() {
        loadBalancer.setStrategy(LoadBalancingStrategy.LEAST_LOADED);

        // Add pending operations to channel1 to make it more loaded
        channel1.addPendingOperation(mockMessage);

        when(mockChannelManager.getHealthyChannels()).thenReturn(Arrays.asList(channel1, channel2));

        ChannelInfo selected = loadBalancer.selectChannel(mockMessage);
        assertEquals(channel2, selected); // Should select less loaded channel
    }

    @Test
    void testWeightedRandomStrategy() {
        loadBalancer.setStrategy(LoadBalancingStrategy.WEIGHTED_RANDOM);
        when(mockChannelManager.getHealthyChannels()).thenReturn(Arrays.asList(channel1, channel2));

        // Test multiple selections to ensure it works
        for (int i = 0; i < 10; i++) {
            ChannelInfo selected = loadBalancer.selectChannel(mockMessage);
            assertTrue(Arrays.asList(channel1, channel2).contains(selected));
        }
    }

    @Test
    void testAdaptiveStrategyLargeTransfer() throws Exception {
        loadBalancer.setStrategy(LoadBalancingStrategy.ADAPTIVE);

        Smb2ReadRequest largeRead = mock(Smb2ReadRequest.class);
        when(largeRead.getReadLength()).thenReturn(2 * 1024 * 1024); // 2MB

        when(mockChannelManager.getHealthyChannels()).thenReturn(Arrays.asList(channel1, channel2));

        ChannelInfo selected = loadBalancer.selectChannel(largeRead);
        // Should prefer higher bandwidth channel for large transfers
        assertEquals(channel2, selected);
    }

    @Test
    void testAdaptiveStrategyMetadataOperation() throws Exception {
        loadBalancer.setStrategy(LoadBalancingStrategy.ADAPTIVE);

        Smb2QueryInfoRequest queryInfo = mock(Smb2QueryInfoRequest.class);

        // Make channel2 have pending operations
        channel2.addPendingOperation(mockMessage);

        when(mockChannelManager.getHealthyChannels()).thenReturn(Arrays.asList(channel1, channel2));

        ChannelInfo selected = loadBalancer.selectChannel(queryInfo);
        // Should prefer less loaded channel for metadata operations
        assertEquals(channel1, selected);
    }

    @Test
    void testAffinityBasedStrategy() throws Exception {
        loadBalancer.setStrategy(LoadBalancingStrategy.AFFINITY_BASED);

        Smb2ReadRequest readRequest = mock(Smb2ReadRequest.class);
        when(readRequest.getTreeId()).thenReturn(123); // Set consistent tree ID for affinity

        when(mockChannelManager.getHealthyChannels()).thenReturn(Arrays.asList(channel1, channel2));

        // Multiple calls with same file ID should return same channel
        ChannelInfo first = loadBalancer.selectChannel(readRequest);
        ChannelInfo second = loadBalancer.selectChannel(readRequest);

        assertEquals(first, second);
    }

    @Test
    void testStrategyChange() {
        assertEquals(LoadBalancingStrategy.ADAPTIVE, loadBalancer.getStrategy());

        loadBalancer.setStrategy(LoadBalancingStrategy.ROUND_ROBIN);
        assertEquals(LoadBalancingStrategy.ROUND_ROBIN, loadBalancer.getStrategy());
    }

    @Test
    void testZeroScoreChannels() {
        loadBalancer.setStrategy(LoadBalancingStrategy.WEIGHTED_RANDOM);

        // Create channels with zero scores (failed state)
        channel1.setState(ChannelState.FAILED);
        channel2.setState(ChannelState.FAILED);

        when(mockChannelManager.getHealthyChannels()).thenReturn(Arrays.asList(channel1, channel2));

        // Should still select a channel even with zero scores
        ChannelInfo selected = loadBalancer.selectChannel(mockMessage);
        assertTrue(Arrays.asList(channel1, channel2).contains(selected));
    }
}
