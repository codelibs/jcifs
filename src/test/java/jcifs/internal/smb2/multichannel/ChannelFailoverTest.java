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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jcifs.SmbTransport;
import jcifs.internal.CommonServerMessageBlock;

/**
 * Unit tests for ChannelFailover
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ChannelFailoverTest {

    @Mock
    private ChannelManager mockChannelManager;

    @Mock
    private ChannelLoadBalancer mockLoadBalancer;

    @Mock
    private SmbTransport mockTransport;

    @Mock
    private SmbTransport mockNewTransport;

    @Mock
    private CommonServerMessageBlock mockOperation;

    private ChannelFailover failover;
    private ChannelInfo failedChannel;

    @BeforeEach
    void setUp() throws UnknownHostException {
        failover = new ChannelFailover(mockChannelManager);

        InetAddress addr = InetAddress.getByName("192.168.1.100");
        NetworkInterfaceInfo localInterface = new NetworkInterfaceInfo(addr, 1000);
        NetworkInterfaceInfo remoteInterface = new NetworkInterfaceInfo(addr, 1000);

        failedChannel = new ChannelInfo("failed-channel", mockTransport, localInterface, remoteInterface);
        failedChannel.setState(ChannelState.ESTABLISHED);

        when(mockChannelManager.getLoadBalancer()).thenReturn(mockLoadBalancer);
    }

    @Test
    void testHandleFailure() {
        IOException error = new IOException("Connection failed");

        failover.handleFailure(failedChannel, error);

        assertEquals(ChannelState.FAILED, failedChannel.getState());
        verify(mockChannelManager).removeChannel(failedChannel);
    }

    @Test
    void testFailoverStateCreation() {
        ChannelFailover.FailoverState state = new ChannelFailover.FailoverState("test-channel");

        assertEquals("test-channel", state.getChannelId());
        assertEquals(0, state.getRetryCount());
        assertTrue(state.shouldRetry());
        assertTrue(state.getFailureTime() > 0);
        assertTrue(state.getNextRetryTime() > state.getFailureTime());
    }

    @Test
    void testFailoverStateRetryLogic() {
        ChannelFailover.FailoverState state = new ChannelFailover.FailoverState("test-channel");

        // Should allow retries up to limit
        assertTrue(state.shouldRetry());

        state.incrementRetry(); // Retry 1
        assertTrue(state.shouldRetry());

        state.incrementRetry(); // Retry 2
        assertTrue(state.shouldRetry());

        state.incrementRetry(); // Retry 3
        assertFalse(state.shouldRetry()); // Max retries reached
    }

    @Test
    void testFailoverStateBackoff() {
        ChannelFailover.FailoverState state = new ChannelFailover.FailoverState("test-channel");

        long firstRetry = state.getNextRetryTime();
        state.incrementRetry();

        long secondRetry = state.getNextRetryTime();
        state.incrementRetry();

        long thirdRetry = state.getNextRetryTime();

        // Should have exponential backoff
        assertTrue(secondRetry > firstRetry);
        assertTrue(thirdRetry > secondRetry);
    }

    @Test
    void testPendingOperationRedistribution() throws Exception {
        // Setup pending operations
        failedChannel.addPendingOperation(mockOperation);

        ChannelInfo alternativeChannel = mock(ChannelInfo.class);
        when(mockLoadBalancer.selectChannel(mockOperation)).thenReturn(alternativeChannel);

        IOException error = new IOException("Connection failed");
        failover.handleFailure(failedChannel, error);

        // Verify pending operations were cleared from failed channel
        assertEquals(0, failedChannel.getRequestsPending());

        // Verify alternative channel was selected and operation added
        verify(mockLoadBalancer).selectChannel(mockOperation);
        verify(alternativeChannel).addPendingOperation(mockOperation);
    }

    @Test
    void testFailureWithNoAlternativeChannels() throws Exception {
        failedChannel.addPendingOperation(mockOperation);

        when(mockLoadBalancer.selectChannel(mockOperation)).thenThrow(new ChannelLoadBalancer.NoAvailableChannelException("No channels"));

        IOException error = new IOException("Connection failed");

        // Should not throw exception even if no alternative channels
        assertDoesNotThrow(() -> failover.handleFailure(failedChannel, error));

        assertEquals(0, failedChannel.getRequestsPending());
    }

    @Test
    void testRecoverySuccess() throws Exception {
        when(mockChannelManager.createTransport(any(), any())).thenReturn(mockNewTransport);
        doNothing().when(mockChannelManager).performChannelBinding(any());

        IOException error = new IOException("Connection failed");
        failover.handleFailure(failedChannel, error);

        // Wait a bit for recovery attempt
        Thread.sleep(100);

        verify(mockChannelManager).createTransport(failedChannel.getLocalInterface(), failedChannel.getRemoteInterface());
    }

    @Test
    void testMultipleFailuresExceedRetryLimit() {
        IOException error = new IOException("Connection failed");

        // Simulate multiple failures
        for (int i = 0; i < 5; i++) {
            failover.handleFailure(failedChannel, error);
        }

        // Should eventually remove the channel
        verify(mockChannelManager, atLeast(1)).removeChannel(failedChannel);
        verify(mockChannelManager, atLeast(1)).establishReplacementChannel();
    }

    @Test
    void testShutdown() {
        failover.shutdown();

        // Should not throw any exceptions
        assertDoesNotThrow(() -> failover.shutdown());
    }

    @Test
    void testConcurrentFailureHandling() throws InterruptedException {
        IOException error = new IOException("Connection failed");

        // Simulate concurrent failures
        Thread[] threads = new Thread[5];
        for (int i = 0; i < threads.length; i++) {
            threads[i] = new Thread(() -> failover.handleFailure(failedChannel, error));
            threads[i].start();
        }

        // Wait for all threads to complete
        for (Thread thread : threads) {
            thread.join(1000);
        }

        assertEquals(ChannelState.FAILED, failedChannel.getState());
    }
}
