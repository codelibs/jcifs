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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.SmbTransport;
import jcifs.internal.CommonServerMessageBlock;

/**
 * Unit tests for ChannelInfo
 */
@ExtendWith(MockitoExtension.class)
class ChannelInfoTest {

    @Mock
    private SmbTransport mockTransport;

    @Mock
    private CommonServerMessageBlock mockOperation;

    private NetworkInterfaceInfo localInterface;
    private NetworkInterfaceInfo remoteInterface;
    private ChannelInfo channelInfo;

    @BeforeEach
    void setUp() throws UnknownHostException {
        InetAddress localAddr = InetAddress.getByName("192.168.1.100");
        InetAddress remoteAddr = InetAddress.getByName("192.168.1.200");

        localInterface = new NetworkInterfaceInfo(localAddr, 1000);
        remoteInterface = new NetworkInterfaceInfo(remoteAddr, 1000);

        channelInfo = new ChannelInfo("test-channel", mockTransport, localInterface, remoteInterface);
    }

    @Test
    void testConstructor() {
        assertEquals("test-channel", channelInfo.getChannelId());
        assertEquals(mockTransport, channelInfo.getTransport());
        assertEquals(localInterface, channelInfo.getLocalInterface());
        assertEquals(remoteInterface, channelInfo.getRemoteInterface());
        assertEquals(ChannelState.DISCONNECTED, channelInfo.getState());
        assertFalse(channelInfo.isPrimary());
        assertEquals(0, channelInfo.getBytesSent());
        assertEquals(0, channelInfo.getBytesReceived());
    }

    @Test
    void testStateTransitions() {
        assertEquals(ChannelState.DISCONNECTED, channelInfo.getState());
        assertFalse(channelInfo.isHealthy());

        channelInfo.setState(ChannelState.ESTABLISHED);
        assertEquals(ChannelState.ESTABLISHED, channelInfo.getState());
        assertTrue(channelInfo.isHealthy());

        channelInfo.setState(ChannelState.ACTIVE);
        assertTrue(channelInfo.isHealthy());

        channelInfo.setState(ChannelState.FAILED);
        assertFalse(channelInfo.isHealthy());
    }

    @Test
    void testActivityTracking() {
        long initialTime = channelInfo.getLastActivityTime();

        // Wait a bit and update activity
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        channelInfo.updateActivity();
        assertTrue(channelInfo.getLastActivityTime() > initialTime);
        assertTrue(channelInfo.getIdleTime() >= 0);
    }

    @Test
    void testMetrics() {
        assertEquals(0, channelInfo.getBytesSent());
        assertEquals(0, channelInfo.getBytesReceived());
        assertEquals(0, channelInfo.getRequestsSent());
        assertEquals(0, channelInfo.getErrors());

        channelInfo.addBytesSent(1000);
        channelInfo.addBytesReceived(2000);
        channelInfo.incrementRequestsSent();
        channelInfo.incrementErrors();

        assertEquals(1000, channelInfo.getBytesSent());
        assertEquals(2000, channelInfo.getBytesReceived());
        assertEquals(1, channelInfo.getRequestsSent());
        assertEquals(1, channelInfo.getErrors());
        assertEquals(1.0, channelInfo.getErrorRate(), 0.01);
    }

    @Test
    void testPendingOperations() {
        assertEquals(0, channelInfo.getRequestsPending());
        assertTrue(channelInfo.getPendingOperations().isEmpty());

        channelInfo.addPendingOperation(mockOperation);
        assertEquals(1, channelInfo.getRequestsPending());
        assertFalse(channelInfo.getPendingOperations().isEmpty());

        assertTrue(channelInfo.removePendingOperation(mockOperation));
        assertEquals(0, channelInfo.getRequestsPending());

        channelInfo.addPendingOperation(mockOperation);
        channelInfo.clearPendingOperations();
        assertEquals(0, channelInfo.getRequestsPending());
    }

    @Test
    void testScoring() {
        channelInfo.setState(ChannelState.ESTABLISHED);
        int baseScore = channelInfo.getScore();
        assertTrue(baseScore > 0);

        // Active channel should have lower score (busy penalty)
        channelInfo.setState(ChannelState.ACTIVE);
        int activeScore = channelInfo.getScore();
        assertTrue(activeScore < baseScore);

        // Failed channel should have zero score
        channelInfo.setState(ChannelState.FAILED);
        assertEquals(0, channelInfo.getScore());

        // Primary channel should have higher score
        channelInfo.setState(ChannelState.ESTABLISHED);
        channelInfo.setPrimary(true);
        int primaryScore = channelInfo.getScore();
        assertTrue(primaryScore > baseScore);

        // High error rate should reduce score
        channelInfo.setState(ChannelState.ESTABLISHED);
        channelInfo.setPrimary(false);
        for (int i = 0; i < 20; i++) {
            channelInfo.incrementRequestsSent();
            channelInfo.incrementErrors(); // 100% error rate
        }
        int highErrorScore = channelInfo.getScore();
        assertTrue(highErrorScore < baseScore);
    }

    @Test
    void testThroughputCalculation() {
        long initialThroughput = channelInfo.getThroughput();
        assertEquals(0, initialThroughput);

        // Add some data transfer
        channelInfo.addBytesSent(1000);
        channelInfo.addBytesReceived(2000);

        // Wait a bit to ensure time passes
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        long throughput = channelInfo.getThroughput();
        assertTrue(throughput > 0);
    }

    @Test
    void testEquals() {
        ChannelInfo other = new ChannelInfo("test-channel", mockTransport, localInterface, remoteInterface);
        assertEquals(channelInfo, other);
        assertEquals(channelInfo.hashCode(), other.hashCode());

        ChannelInfo different = new ChannelInfo("different-channel", mockTransport, localInterface, remoteInterface);
        assertNotEquals(channelInfo, different);
    }

    @Test
    void testToString() {
        String str = channelInfo.toString();
        assertNotNull(str);
        assertTrue(str.contains("test-channel"));
        assertTrue(str.contains(ChannelState.DISCONNECTED.toString()));
    }
}
