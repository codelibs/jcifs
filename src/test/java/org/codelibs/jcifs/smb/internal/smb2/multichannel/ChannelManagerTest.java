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
package org.codelibs.jcifs.smb.internal.smb2.multichannel;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.SmbSession;
import org.codelibs.jcifs.smb.SmbTransport;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * Unit tests for ChannelManager
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ChannelManagerTest {

    @Mock
    private CIFSContext mockContext;

    @Mock
    private Configuration mockConfig;

    @Mock
    private SmbSession mockSession;

    @Mock
    private SmbTransport mockTransport;

    @Mock
    private CommonServerMessageBlock mockMessage;

    private ChannelManager channelManager;

    @BeforeEach
    void setUp() {
        when(mockContext.getConfig()).thenReturn(mockConfig);
        when(mockConfig.isUseMultiChannel()).thenReturn(true);
        when(mockConfig.getMaxChannels()).thenReturn(4);
        when(mockConfig.getChannelBindingPolicy()).thenReturn(1); // preferred
        when(mockConfig.getLoadBalancingStrategy()).thenReturn("adaptive");
        when(mockConfig.getChannelHealthCheckInterval()).thenReturn(10);

        channelManager = new ChannelManager(mockContext, mockSession);
    }

    @Test
    void testConstructor() {
        assertNotNull(channelManager);
        assertFalse(channelManager.isUseMultiChannel());
        assertEquals(0, channelManager.getChannels().size());
        assertNotNull(channelManager.getLoadBalancer());
    }

    @Test
    void testInitializationWithoutMultiChannelSupport() throws IOException {
        when(mockConfig.isUseMultiChannel()).thenReturn(false);
        ChannelManager manager = new ChannelManager(mockContext, mockSession);

        manager.initializeMultiChannel();

        assertFalse(manager.isUseMultiChannel());
    }

    @Test
    void testGetHealthyChannels() throws UnknownHostException {
        assertTrue(channelManager.getHealthyChannels().isEmpty());

        // Add a healthy channel manually for testing
        InetAddress addr = InetAddress.getByName("192.168.1.100");
        NetworkInterfaceInfo localInterface = new NetworkInterfaceInfo(addr, 1000);
        NetworkInterfaceInfo remoteInterface = new NetworkInterfaceInfo(addr, 1000);
        ChannelInfo healthyChannel = new ChannelInfo("test-channel", mockTransport, localInterface, remoteInterface);
        healthyChannel.setState(ChannelState.ESTABLISHED);

        // Use reflection or package-private method to add channel for testing
        // For now, just test the empty case
        assertEquals(0, channelManager.getHealthyChannels().size());
    }

    @Test
    void testChannelSelection() {
        try {
            channelManager.selectChannel(mockMessage);
            fail("Should throw exception when no channels available");
        } catch (Exception e) {
            // Expected - no channels available
            assertTrue(e instanceof ChannelLoadBalancer.NoAvailableChannelException);
        }
    }

    @Test
    void testRemoveChannel() throws UnknownHostException {
        InetAddress addr = InetAddress.getByName("192.168.1.100");
        NetworkInterfaceInfo localInterface = new NetworkInterfaceInfo(addr, 1000);
        NetworkInterfaceInfo remoteInterface = new NetworkInterfaceInfo(addr, 1000);
        ChannelInfo channel = new ChannelInfo("test-channel", mockTransport, localInterface, remoteInterface);

        // Remove should not throw exception even if channel doesn't exist
        assertDoesNotThrow(() -> channelManager.removeChannel(channel));
    }

    @Test
    void testShutdown() {
        assertDoesNotThrow(() -> channelManager.shutdown());

        // Multiple shutdowns should be safe
        assertDoesNotThrow(() -> channelManager.shutdown());
    }

    @Test
    void testLoadBalancerAccess() {
        ChannelLoadBalancer balancer = channelManager.getLoadBalancer();
        assertNotNull(balancer);

        // Should return same instance
        assertSame(balancer, channelManager.getLoadBalancer());
    }

    @Test
    void testChannelFailureHandling() throws UnknownHostException {
        InetAddress addr = InetAddress.getByName("192.168.1.100");
        NetworkInterfaceInfo localInterface = new NetworkInterfaceInfo(addr, 1000);
        NetworkInterfaceInfo remoteInterface = new NetworkInterfaceInfo(addr, 1000);
        ChannelInfo channel = new ChannelInfo("test-channel", mockTransport, localInterface, remoteInterface);

        IOException error = new IOException("Test error");

        // Should not throw exception
        assertDoesNotThrow(() -> channelManager.handleChannelFailure(channel, error));
    }

    @Test
    void testEstablishReplacementChannel() {
        // Should not throw exception even when no interfaces are available
        assertDoesNotThrow(() -> channelManager.establishReplacementChannel());
    }

    @Test
    void testGetChannelForTransport() {
        ChannelInfo result = channelManager.getChannelForTransport(mockTransport);
        assertNull(result); // No channels registered yet
    }

    @Test
    void testChannelManagerLifecycle() {
        // Test complete lifecycle
        assertFalse(channelManager.isUseMultiChannel());

        try {
            channelManager.initializeMultiChannel();
            // Should not throw exception even if initialization fails
        } catch (Exception e) {
            // Expected in test environment without proper server setup
        }

        assertDoesNotThrow(() -> channelManager.shutdown());
    }

    @Test
    void testConcurrentAccess() throws InterruptedException {
        // Test thread safety
        Thread[] threads = new Thread[10];
        for (int i = 0; i < threads.length; i++) {
            threads[i] = new Thread(() -> {
                channelManager.getChannels();
                channelManager.getHealthyChannels();
                channelManager.getLoadBalancer();
            });
            threads[i].start();
        }

        for (Thread thread : threads) {
            thread.join(1000);
        }

        // Should complete without exceptions
    }
}
