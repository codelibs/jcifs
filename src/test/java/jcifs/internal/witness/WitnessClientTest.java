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
package jcifs.internal.witness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.InetAddress;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.witness.WitnessRegistration.WitnessRegistrationState;

/**
 * Unit tests for WitnessClient class using mocks.
 */
@ExtendWith(MockitoExtension.class)
public class WitnessClientTest {

    @Mock
    private CIFSContext mockContext;

    @Mock
    private Configuration mockConfig;

    @Mock
    private WitnessRpcClient mockRpcClient;

    private InetAddress witnessServer;
    private InetAddress serverAddress;

    @BeforeEach
    void setUp() throws Exception {
        witnessServer = InetAddress.getByName("192.168.1.200");
        serverAddress = InetAddress.getByName("192.168.1.100");

        // Setup mock configuration with lenient stubbing
        lenient().when(mockContext.getConfig()).thenReturn(mockConfig);
        lenient().when(mockConfig.getWitnessHeartbeatTimeout()).thenReturn(120000L);
        lenient().when(mockConfig.getWitnessRegistrationTimeout()).thenReturn(300000L);
        lenient().when(mockConfig.getWitnessReconnectDelay()).thenReturn(1000L);
        lenient().when(mockConfig.isWitnessServiceDiscovery()).thenReturn(true);
    }

    @Test
    void testSuccessfulRegistration() throws Exception {
        // Setup mock RPC response
        WitnessRegisterResponse mockResponse = mock(WitnessRegisterResponse.class);
        lenient().when(mockResponse.isSuccess()).thenReturn(true);
        lenient().when(mockResponse.getRegistrationId()).thenReturn("test-reg-123");

        WitnessRpcClient mockRpc = mock(WitnessRpcClient.class);
        lenient().when(mockRpc.register(any(WitnessRegisterRequest.class))).thenReturn(mockResponse);

        // Create a test witness client that uses our mock RPC client
        TestWitnessClient client = new TestWitnessClient(witnessServer, mockContext, mockRpc);

        TestNotificationListener listener = new TestNotificationListener();

        CompletableFuture<WitnessRegistration> future = client.registerForNotifications("\\\\server\\share", serverAddress, listener);

        WitnessRegistration registration = future.get(5, TimeUnit.SECONDS);

        assertNotNull(registration);
        assertEquals(WitnessRegistrationState.REGISTERED, registration.getState());
        assertEquals("\\\\server\\share", registration.getShareName());
        assertEquals(serverAddress, registration.getServerAddress());
        assertEquals(WitnessServiceType.FILE_SERVER_WITNESS, registration.getServiceType());

        verify(mockRpc).register(any(WitnessRegisterRequest.class));

        client.close();
    }

    @Test
    void testFailedRegistration() throws Exception {
        // Setup mock RPC response for failure
        WitnessRegisterResponse mockResponse = mock(WitnessRegisterResponse.class);
        when(mockResponse.isSuccess()).thenReturn(false);
        when(mockResponse.getError()).thenReturn("Registration failed");

        WitnessRpcClient mockRpc = mock(WitnessRpcClient.class);
        lenient().when(mockRpc.register(any(WitnessRegisterRequest.class))).thenReturn(mockResponse);

        TestWitnessClient client = new TestWitnessClient(witnessServer, mockContext, mockRpc);

        TestNotificationListener listener = new TestNotificationListener();

        CompletableFuture<WitnessRegistration> future = client.registerForNotifications("\\\\server\\share", serverAddress, listener);

        assertThrows(Exception.class, () -> {
            future.get(5, TimeUnit.SECONDS);
        });

        client.close();
    }

    @Test
    void testNotificationDelivery() throws Exception {
        // Setup successful registration
        WitnessRegisterResponse mockResponse = mock(WitnessRegisterResponse.class);
        lenient().when(mockResponse.isSuccess()).thenReturn(true);
        lenient().when(mockResponse.getRegistrationId()).thenReturn("test-reg-123");

        WitnessRpcClient mockRpc = mock(WitnessRpcClient.class);
        lenient().when(mockRpc.register(any(WitnessRegisterRequest.class))).thenReturn(mockResponse);

        TestWitnessClient client = new TestWitnessClient(witnessServer, mockContext, mockRpc);

        TestNotificationListener listener = new TestNotificationListener();

        // Register for notifications
        WitnessRegistration registration =
                client.registerForNotifications("\\\\server\\share", serverAddress, listener).get(5, TimeUnit.SECONDS);

        // Create and process a notification
        WitnessNotification notification = new WitnessNotification(WitnessEventType.CLIENT_MOVE, "\\\\server\\share");
        notification.addNewIPAddress(InetAddress.getByName("192.168.1.101"));

        client.processNotification(notification);

        // Verify notification was delivered
        assertTrue(listener.waitForNotification(1000));
        assertNotNull(listener.getLastNotification());
        assertEquals(WitnessEventType.CLIENT_MOVE, listener.getLastNotification().getEventType());

        client.close();
    }

    @Test
    void testUnregistration() throws Exception {
        // Setup successful registration
        WitnessRegisterResponse registerResponse = mock(WitnessRegisterResponse.class);
        lenient().when(registerResponse.isSuccess()).thenReturn(true);
        lenient().when(registerResponse.getRegistrationId()).thenReturn("test-reg-123");

        // Setup successful unregistration
        WitnessUnregisterResponse unregisterResponse = mock(WitnessUnregisterResponse.class);
        lenient().when(unregisterResponse.isSuccess()).thenReturn(true);

        WitnessRpcClient mockRpc = mock(WitnessRpcClient.class);
        lenient().when(mockRpc.register(any(WitnessRegisterRequest.class))).thenReturn(registerResponse);
        lenient().when(mockRpc.unregister(any(WitnessUnregisterRequest.class))).thenReturn(unregisterResponse);

        TestWitnessClient client = new TestWitnessClient(witnessServer, mockContext, mockRpc);

        TestNotificationListener listener = new TestNotificationListener();

        // Register
        WitnessRegistration registration =
                client.registerForNotifications("\\\\server\\share", serverAddress, listener).get(5, TimeUnit.SECONDS);

        assertEquals(1, client.getActiveRegistrationCount());

        // Unregister
        client.unregister(registration).get(5, TimeUnit.SECONDS);

        assertEquals(0, client.getActiveRegistrationCount());

        verify(mockRpc).register(any(WitnessRegisterRequest.class));
        verify(mockRpc).unregister(any(WitnessUnregisterRequest.class));

        client.close();
    }

    @Test
    void testGetWitnessServer() throws Exception {
        WitnessRpcClient mockRpc = mock(WitnessRpcClient.class);
        TestWitnessClient client = new TestWitnessClient(witnessServer, mockContext, mockRpc);

        assertEquals(witnessServer, client.getWitnessServer());

        client.close();
    }

    /**
     * Test notification listener that captures notifications
     */
    private static class TestNotificationListener implements WitnessClient.WitnessNotificationListener {
        private final CountDownLatch notificationLatch = new CountDownLatch(1);
        private volatile WitnessNotification lastNotification;

        @Override
        public void onWitnessNotification(WitnessNotification notification) {
            this.lastNotification = notification;
            notificationLatch.countDown();
        }

        @Override
        public void onRegistrationFailed(WitnessRegistration registration, Exception error) {
            // Test implementation
        }

        @Override
        public void onRegistrationExpired(WitnessRegistration registration) {
            // Test implementation
        }

        public boolean waitForNotification(long timeoutMs) throws InterruptedException {
            return notificationLatch.await(timeoutMs, TimeUnit.MILLISECONDS);
        }

        public WitnessNotification getLastNotification() {
            return lastNotification;
        }
    }

    /**
     * Test witness client that allows injection of mock RPC client
     */
    private static class TestWitnessClient extends WitnessClient {

        public TestWitnessClient(InetAddress witnessServer, CIFSContext context, WitnessRpcClient rpcClient) {
            super(witnessServer, context, rpcClient);
        }

        // TestWitnessClient can use the parent implementation now since we inject the mock RPC client
    }
}
