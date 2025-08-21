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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Properties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.config.PropertyConfiguration;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.smb.SmbSessionInternal;
import jcifs.smb.SmbTransportInternal;

/**
 * Unit tests for SMB3 Multi-Channel functionality
 *
 * These tests verify the multi-channel implementation without requiring a real SMB server.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MultiChannelIntegrationTest {

    @Mock
    private SmbTransportInternal mockTransport;

    @Mock
    private CIFSContext mockContext;

    @Mock
    private SmbSessionInternal mockSession;

    @Mock
    private Configuration mockConfig;

    private ChannelManager channelManager;
    private PropertyConfiguration multiConfig;

    @BeforeEach
    void setUp() throws CIFSException {
        // Setup multi-channel configuration
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.useMultiChannel", "true");
        props.setProperty("jcifs.smb.client.maxChannels", "4");
        props.setProperty("jcifs.smb.client.loadBalancingStrategy", "adaptive");
        props.setProperty("jcifs.smb.client.channelHealthCheckInterval", "5");

        multiConfig = new PropertyConfiguration(props);

        // Mock context and session for ChannelManager
        when(mockContext.getConfig()).thenReturn(multiConfig);
        when(mockSession.getSessionKey()).thenReturn(new byte[16]);

        channelManager = new ChannelManager(mockContext, mockSession);
    }

    @Test
    void testMultiChannelInitialization() throws Exception {
        // Test that ChannelManager initializes properly
        assertNotNull(channelManager);
        assertNotNull(channelManager.getChannels());
        // Note: isUseMultiChannel() checks if actual multi-channel is negotiated with server
        // In mock environment, this will be false until we mock successful negotiation

        // Verify load balancer is initialized
        assertNotNull(channelManager.getLoadBalancer());
    }

    @Test
    void testNetworkInterfaceInfo() throws Exception {
        // Test NetworkInterfaceInfo creation and scoring
        InetAddress address = InetAddress.getByName("192.168.1.100");
        NetworkInterfaceInfo nic = new NetworkInterfaceInfo(address, 1);

        nic.setInterfaceIndex(1);
        nic.setCapability(Smb2ChannelCapabilities.NETWORK_INTERFACE_CAP_RSS);
        nic.setLinkSpeed(10000);

        // Verify properties
        assertEquals(1, nic.getInterfaceIndex());
        assertEquals(10000, nic.getLinkSpeed());
        assertTrue(nic.isRssCapable());
        assertFalse(nic.isRdmaCapable());
        assertEquals(address, nic.getAddress());

        // Test scoring
        int score = nic.getScore();
        assertEquals(11000, score); // 10000 (link speed) + 1000 (RSS bonus)

        // Test encoding/decoding
        byte[] encoded = nic.encode();
        assertNotNull(encoded);
        assertEquals(Smb2ChannelCapabilities.NETWORK_INTERFACE_INFO_SIZE, encoded.length);

        NetworkInterfaceInfo decoded = NetworkInterfaceInfo.decode(encoded, 0);
        assertEquals(nic.getInterfaceIndex(), decoded.getInterfaceIndex());
        assertEquals(nic.getLinkSpeed(), decoded.getLinkSpeed());
        assertEquals(nic.isRssCapable(), decoded.isRssCapable());
    }

    @Test
    void testChannelInfoCreation() throws Exception {
        // Test ChannelInfo creation
        InetAddress localAddr = InetAddress.getByName("192.168.1.10");
        InetAddress remoteAddr = InetAddress.getByName("192.168.1.100");

        NetworkInterfaceInfo localNic = new NetworkInterfaceInfo(localAddr, 1);
        NetworkInterfaceInfo remoteNic = new NetworkInterfaceInfo(remoteAddr, 445);

        // Mock transport doesn't have isConnected, but we can work around it

        ChannelInfo channel = new ChannelInfo("test-channel", mockTransport, localNic, remoteNic);
        channel.setState(ChannelState.ESTABLISHED);

        // Verify channel properties
        assertEquals("test-channel", channel.getChannelId());
        assertEquals(mockTransport, channel.getTransport());
        assertEquals(localNic, channel.getLocalInterface());
        assertEquals(remoteNic, channel.getRemoteInterface());
        assertEquals(ChannelState.ESTABLISHED, channel.getState());
        assertTrue(channel.isHealthy());

        // Test metrics
        channel.incrementRequestsSent();
        channel.addBytesSent(1024);
        channel.updateActivity();

        assertEquals(1, channel.getRequestsSent());
        assertEquals(1024, channel.getBytesSent());
        assertTrue(channel.getLastActivityTime() > 0);
    }

    @Test
    void testChannelFailover() throws Exception {
        // Test failover mechanism
        ChannelFailover failover = new ChannelFailover(channelManager);

        // Create a channel
        InetAddress addr = InetAddress.getByName("192.168.1.100");
        NetworkInterfaceInfo nic = new NetworkInterfaceInfo(addr, 445);

        // Mock transport doesn't have isConnected, but we can work around it
        ChannelInfo channel = new ChannelInfo("failover-test", mockTransport, nic, nic);
        channel.setState(ChannelState.ESTABLISHED);

        // Simulate failure
        IOException failure = new IOException("Connection lost");
        failover.handleFailure(channel, failure);

        // Verify channel state changed
        assertFalse(channel.isHealthy());
        assertEquals(ChannelState.FAILED, channel.getState());
    }

    @Test
    void testLoadBalancingStrategies() throws Exception {
        // Test different load balancing strategies
        ChannelLoadBalancer loadBalancer = new ChannelLoadBalancer(channelManager);

        // Test setting different strategies
        LoadBalancingStrategy[] strategies = { LoadBalancingStrategy.ROUND_ROBIN, LoadBalancingStrategy.LEAST_LOADED,
                LoadBalancingStrategy.WEIGHTED_RANDOM, LoadBalancingStrategy.AFFINITY_BASED, LoadBalancingStrategy.ADAPTIVE };

        for (LoadBalancingStrategy strategy : strategies) {
            loadBalancer.setStrategy(strategy);
            assertEquals(strategy, loadBalancer.getStrategy());
        }

        // Test channel selection with mock request when no channels available
        ServerMessageBlock2Request mockRequest = mock(ServerMessageBlock2Request.class);
        when(mockRequest.getTreeId()).thenReturn(123);

        // Should throw NoAvailableChannelException when no healthy channels
        assertThrows(ChannelLoadBalancer.NoAvailableChannelException.class, () -> loadBalancer.selectChannel(mockRequest),
                "Should throw exception when no healthy channels available");
    }
}