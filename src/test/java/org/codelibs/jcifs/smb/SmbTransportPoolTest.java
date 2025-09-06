package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Comprehensive test suite for SmbTransportPool interface.
 * Tests all transport pool operations including connection management,
 * authentication, and lifecycle operations.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SmbTransportPool Tests")
class SmbTransportPoolTest {

    @Mock
    private SmbTransportPool transportPool;

    @Mock
    private CIFSContext context;

    @Mock
    private Address address;

    @Mock
    private SmbTransport transport;

    @Mock
    private InetAddress localAddr;

    private static final int DEFAULT_PORT = 445;
    private static final String TEST_HOST = "test.server.com";
    private static final int LOCAL_PORT = 12345;

    @BeforeEach
    void setUp() {
        // Common setup for all tests
    }

    @Nested
    @DisplayName("GetSmbTransport Methods")
    class GetSmbTransportTests {

        @Test
        @DisplayName("Should get transport by name with default parameters")
        void testGetSmbTransportByName() throws UnknownHostException, IOException {
            // Given
            when(transportPool.getSmbTransport(context, TEST_HOST, DEFAULT_PORT, false, false)).thenReturn(transport);

            // When
            SmbTransport result = transportPool.getSmbTransport(context, TEST_HOST, DEFAULT_PORT, false, false);

            // Then
            assertNotNull(result);
            assertEquals(transport, result);
            verify(transportPool).getSmbTransport(context, TEST_HOST, DEFAULT_PORT, false, false);
        }

        @Test
        @DisplayName("Should get transport by name with exclusive connection")
        void testGetSmbTransportByNameExclusive() throws UnknownHostException, IOException {
            // Given
            when(transportPool.getSmbTransport(context, TEST_HOST, DEFAULT_PORT, true, false)).thenReturn(transport);

            // When
            SmbTransport result = transportPool.getSmbTransport(context, TEST_HOST, DEFAULT_PORT, true, false);

            // Then
            assertNotNull(result);
            assertEquals(transport, result);
            verify(transportPool).getSmbTransport(context, TEST_HOST, DEFAULT_PORT, true, false);
        }

        @Test
        @DisplayName("Should get transport by name with forced signing")
        void testGetSmbTransportByNameForceSigning() throws UnknownHostException, IOException {
            // Given
            when(transportPool.getSmbTransport(context, TEST_HOST, DEFAULT_PORT, false, true)).thenReturn(transport);

            // When
            SmbTransport result = transportPool.getSmbTransport(context, TEST_HOST, DEFAULT_PORT, false, true);

            // Then
            assertNotNull(result);
            assertEquals(transport, result);
            verify(transportPool).getSmbTransport(context, TEST_HOST, DEFAULT_PORT, false, true);
        }

        @Test
        @DisplayName("Should handle UnknownHostException")
        void testGetSmbTransportUnknownHost() throws UnknownHostException, IOException {
            // Given
            when(transportPool.getSmbTransport(context, "unknown.host", DEFAULT_PORT, false, false))
                    .thenThrow(new UnknownHostException("Unknown host"));

            // When & Then
            assertThrows(UnknownHostException.class,
                    () -> transportPool.getSmbTransport(context, "unknown.host", DEFAULT_PORT, false, false));
        }

        @Test
        @DisplayName("Should handle IOException")
        void testGetSmbTransportIOException() throws UnknownHostException, IOException {
            // Given
            when(transportPool.getSmbTransport(context, TEST_HOST, DEFAULT_PORT, false, false))
                    .thenThrow(new IOException("Connection failed"));

            // When & Then
            assertThrows(IOException.class, () -> transportPool.getSmbTransport(context, TEST_HOST, DEFAULT_PORT, false, false));
        }

        @Test
        @DisplayName("Should get transport by address without signing")
        void testGetSmbTransportByAddress() {
            // Given
            when(transportPool.getSmbTransport(context, address, DEFAULT_PORT, false)).thenReturn(transport);

            // When
            SmbTransport result = transportPool.getSmbTransport(context, address, DEFAULT_PORT, false);

            // Then
            assertNotNull(result);
            assertEquals(transport, result);
            verify(transportPool).getSmbTransport(context, address, DEFAULT_PORT, false);
        }

        @Test
        @DisplayName("Should get transport by address with forced signing")
        void testGetSmbTransportByAddressWithSigning() {
            // Given
            when(transportPool.getSmbTransport(context, address, DEFAULT_PORT, false, true)).thenReturn(transport);

            // When
            SmbTransport result = transportPool.getSmbTransport(context, address, DEFAULT_PORT, false, true);

            // Then
            assertNotNull(result);
            assertEquals(transport, result);
            verify(transportPool).getSmbTransport(context, address, DEFAULT_PORT, false, true);
        }

        @Test
        @DisplayName("Should get transport with local binding")
        void testGetSmbTransportWithLocalBinding() {
            // Given
            when(transportPool.getSmbTransport(context, address, DEFAULT_PORT, localAddr, LOCAL_PORT, TEST_HOST, false))
                    .thenReturn(transport);

            // When
            SmbTransport result = transportPool.getSmbTransport(context, address, DEFAULT_PORT, localAddr, LOCAL_PORT, TEST_HOST, false);

            // Then
            assertNotNull(result);
            assertEquals(transport, result);
            verify(transportPool).getSmbTransport(context, address, DEFAULT_PORT, localAddr, LOCAL_PORT, TEST_HOST, false);
        }

        @Test
        @DisplayName("Should get transport with local binding and forced signing")
        void testGetSmbTransportWithLocalBindingAndSigning() {
            // Given
            when(transportPool.getSmbTransport(context, address, DEFAULT_PORT, localAddr, LOCAL_PORT, TEST_HOST, false, true))
                    .thenReturn(transport);

            // When
            SmbTransport result =
                    transportPool.getSmbTransport(context, address, DEFAULT_PORT, localAddr, LOCAL_PORT, TEST_HOST, false, true);

            // Then
            assertNotNull(result);
            assertEquals(transport, result);
            verify(transportPool).getSmbTransport(context, address, DEFAULT_PORT, localAddr, LOCAL_PORT, TEST_HOST, false, true);
        }

        @Test
        @DisplayName("Should handle null address")
        void testGetSmbTransportNullAddress() {
            // Given
            when(transportPool.getSmbTransport(context, null, DEFAULT_PORT, false)).thenReturn(null);

            // When
            SmbTransport result = transportPool.getSmbTransport(context, null, DEFAULT_PORT, false);

            // Then
            assertEquals(null, result);
        }

        @Test
        @DisplayName("Should handle negative port")
        void testGetSmbTransportNegativePort() {
            // Given
            when(transportPool.getSmbTransport(context, address, -1, false)).thenReturn(transport);

            // When
            SmbTransport result = transportPool.getSmbTransport(context, address, -1, false);

            // Then
            assertNotNull(result);
            assertEquals(transport, result);
        }
    }

    @Nested
    @DisplayName("Transport Management")
    class TransportManagementTests {

        @Test
        @DisplayName("Should remove transport from pool")
        void testRemoveTransport() {
            // Given
            doNothing().when(transportPool).removeTransport(transport);

            // When
            transportPool.removeTransport(transport);

            // Then
            verify(transportPool).removeTransport(transport);
        }

        @Test
        @DisplayName("Should handle null transport removal")
        void testRemoveNullTransport() {
            // Given
            doNothing().when(transportPool).removeTransport(null);

            // When
            transportPool.removeTransport(null);

            // Then
            verify(transportPool).removeTransport(null);
        }

        @Test
        @DisplayName("Should remove multiple transports")
        void testRemoveMultipleTransports() {
            // Given
            SmbTransport transport2 = mock(SmbTransport.class);
            doNothing().when(transportPool).removeTransport(any());

            // When
            transportPool.removeTransport(transport);
            transportPool.removeTransport(transport2);

            // Then
            verify(transportPool).removeTransport(transport);
            verify(transportPool).removeTransport(transport2);
        }
    }

    @Nested
    @DisplayName("Pool Lifecycle")
    class PoolLifecycleTests {

        @Test
        @DisplayName("Should close pool successfully with no active transports")
        void testClosePoolNoActiveTransports() throws CIFSException {
            // Given
            when(transportPool.close()).thenReturn(false);

            // When
            boolean result = transportPool.close();

            // Then
            assertFalse(result);
            verify(transportPool).close();
        }

        @Test
        @DisplayName("Should close pool with active transports")
        void testClosePoolWithActiveTransports() throws CIFSException {
            // Given
            when(transportPool.close()).thenReturn(true);

            // When
            boolean result = transportPool.close();

            // Then
            assertTrue(result);
            verify(transportPool).close();
        }

        @Test
        @DisplayName("Should handle exception during close")
        void testClosePoolException() throws CIFSException {
            // Given
            when(transportPool.close()).thenThrow(new CIFSException("Close failed"));

            // When & Then
            assertThrows(CIFSException.class, () -> transportPool.close());
        }

        @Test
        @DisplayName("Should close pool multiple times")
        void testClosePoolMultipleTimes() throws CIFSException {
            // Given
            when(transportPool.close()).thenReturn(false);

            // When
            boolean result1 = transportPool.close();
            boolean result2 = transportPool.close();

            // Then
            assertFalse(result1);
            assertFalse(result2);
            verify(transportPool, times(2)).close();
        }
    }

    @Nested
    @DisplayName("Authentication Methods (Deprecated)")
    class AuthenticationTests {

        @Test
        @DisplayName("Should perform logon with address")
        void testLogonWithAddress() throws CIFSException {
            // Given
            doNothing().when(transportPool).logon(context, address);

            // When
            transportPool.logon(context, address);

            // Then
            verify(transportPool).logon(context, address);
        }

        @Test
        @DisplayName("Should perform logon with address and port")
        void testLogonWithAddressAndPort() throws CIFSException {
            // Given
            doNothing().when(transportPool).logon(context, address, DEFAULT_PORT);

            // When
            transportPool.logon(context, address, DEFAULT_PORT);

            // Then
            verify(transportPool).logon(context, address, DEFAULT_PORT);
        }

        @Test
        @DisplayName("Should handle authentication failure during logon")
        void testLogonAuthenticationFailure() throws CIFSException {
            // Given
            doThrow(new CIFSException("Authentication failed")).when(transportPool).logon(context, address);

            // When & Then
            assertThrows(CIFSException.class, () -> transportPool.logon(context, address));
        }

        @Test
        @DisplayName("Should get NTLM challenge with address")
        void testGetChallengeWithAddress() throws CIFSException {
            // Given
            byte[] expectedChallenge = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            when(transportPool.getChallenge(context, address)).thenReturn(expectedChallenge);

            // When
            byte[] result = transportPool.getChallenge(context, address);

            // Then
            assertNotNull(result);
            assertArrayEquals(expectedChallenge, result);
            verify(transportPool).getChallenge(context, address);
        }

        @Test
        @DisplayName("Should get NTLM challenge with address and port")
        void testGetChallengeWithAddressAndPort() throws CIFSException {
            // Given
            byte[] expectedChallenge = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
            when(transportPool.getChallenge(context, address, DEFAULT_PORT)).thenReturn(expectedChallenge);

            // When
            byte[] result = transportPool.getChallenge(context, address, DEFAULT_PORT);

            // Then
            assertNotNull(result);
            assertArrayEquals(expectedChallenge, result);
            verify(transportPool).getChallenge(context, address, DEFAULT_PORT);
        }

        @Test
        @DisplayName("Should handle null challenge response")
        void testGetChallengeNull() throws CIFSException {
            // Given
            when(transportPool.getChallenge(context, address)).thenReturn(null);

            // When
            byte[] result = transportPool.getChallenge(context, address);

            // Then
            assertEquals(null, result);
            verify(transportPool).getChallenge(context, address);
        }

        @Test
        @DisplayName("Should handle exception when getting challenge")
        void testGetChallengeException() throws CIFSException {
            // Given
            when(transportPool.getChallenge(context, address)).thenThrow(new CIFSException("Failed to get challenge"));

            // When & Then
            assertThrows(CIFSException.class, () -> transportPool.getChallenge(context, address));
        }
    }

    @Nested
    @DisplayName("Edge Cases and Error Handling")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle null context")
        void testNullContext() {
            // Given
            when(transportPool.getSmbTransport(null, address, DEFAULT_PORT, false)).thenReturn(null);

            // When
            SmbTransport result = transportPool.getSmbTransport(null, address, DEFAULT_PORT, false);

            // Then
            assertEquals(null, result);
        }

        @Test
        @DisplayName("Should handle zero port")
        void testZeroPort() {
            // Given
            when(transportPool.getSmbTransport(context, address, 0, false)).thenReturn(transport);

            // When
            SmbTransport result = transportPool.getSmbTransport(context, address, 0, false);

            // Then
            assertNotNull(result);
            assertEquals(transport, result);
        }

        @Test
        @DisplayName("Should handle maximum port value")
        void testMaxPortValue() {
            // Given
            int maxPort = 65535;
            when(transportPool.getSmbTransport(context, address, maxPort, false)).thenReturn(transport);

            // When
            SmbTransport result = transportPool.getSmbTransport(context, address, maxPort, false);

            // Then
            assertNotNull(result);
            assertEquals(transport, result);
        }

        @Test
        @DisplayName("Should handle null hostname in local binding")
        void testNullHostnameInLocalBinding() {
            // Given
            when(transportPool.getSmbTransport(context, address, DEFAULT_PORT, localAddr, LOCAL_PORT, null, false)).thenReturn(transport);

            // When
            SmbTransport result = transportPool.getSmbTransport(context, address, DEFAULT_PORT, localAddr, LOCAL_PORT, null, false);

            // Then
            assertNotNull(result);
            assertEquals(transport, result);
        }

        @Test
        @DisplayName("Should handle null local address")
        void testNullLocalAddress() {
            // Given
            when(transportPool.getSmbTransport(context, address, DEFAULT_PORT, null, LOCAL_PORT, TEST_HOST, false)).thenReturn(transport);

            // When
            SmbTransport result = transportPool.getSmbTransport(context, address, DEFAULT_PORT, null, LOCAL_PORT, TEST_HOST, false);

            // Then
            assertNotNull(result);
            assertEquals(transport, result);
        }
    }

    @Nested
    @DisplayName("Concurrent Operations")
    class ConcurrentOperationsTests {

        @Test
        @DisplayName("Should handle concurrent transport requests")
        void testConcurrentTransportRequests() throws InterruptedException {
            // Given
            when(transportPool.getSmbTransport(any(), any(Address.class), anyInt(), anyBoolean())).thenReturn(transport);

            // When - simulate concurrent requests
            Thread thread1 = new Thread(() -> transportPool.getSmbTransport(context, address, DEFAULT_PORT, false));
            Thread thread2 = new Thread(() -> transportPool.getSmbTransport(context, address, DEFAULT_PORT, true));

            thread1.start();
            thread2.start();
            thread1.join();
            thread2.join();

            // Then
            verify(transportPool, times(2)).getSmbTransport(any(), any(Address.class), anyInt(), anyBoolean());
        }

        @Test
        @DisplayName("Should handle concurrent remove operations")
        void testConcurrentRemoveOperations() throws InterruptedException {
            // Given
            SmbTransport transport2 = mock(SmbTransport.class);
            doNothing().when(transportPool).removeTransport(any());

            // When - simulate concurrent removes
            Thread thread1 = new Thread(() -> transportPool.removeTransport(transport));
            Thread thread2 = new Thread(() -> transportPool.removeTransport(transport2));

            thread1.start();
            thread2.start();
            thread1.join();
            thread2.join();

            // Then
            verify(transportPool).removeTransport(transport);
            verify(transportPool).removeTransport(transport2);
        }
    }

    @Nested
    @DisplayName("Integration Scenarios")
    class IntegrationTests {

        @Test
        @DisplayName("Should complete full connection lifecycle")
        void testFullConnectionLifecycle() throws Exception {
            // Given
            when(transportPool.getSmbTransport(context, TEST_HOST, DEFAULT_PORT, false, false)).thenReturn(transport);
            doNothing().when(transportPool).removeTransport(transport);
            when(transportPool.close()).thenReturn(false);

            // When - complete lifecycle
            SmbTransport retrievedTransport = transportPool.getSmbTransport(context, TEST_HOST, DEFAULT_PORT, false, false);
            transportPool.removeTransport(retrievedTransport);
            boolean hasActiveTransports = transportPool.close();

            // Then
            assertNotNull(retrievedTransport);
            assertFalse(hasActiveTransports);
            verify(transportPool).getSmbTransport(context, TEST_HOST, DEFAULT_PORT, false, false);
            verify(transportPool).removeTransport(transport);
            verify(transportPool).close();
        }

        @Test
        @DisplayName("Should handle authentication workflow")
        void testAuthenticationWorkflow() throws CIFSException {
            // Given
            byte[] challenge = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            when(transportPool.getChallenge(context, address)).thenReturn(challenge);
            doNothing().when(transportPool).logon(context, address);

            // When
            byte[] retrievedChallenge = transportPool.getChallenge(context, address);
            transportPool.logon(context, address);

            // Then
            assertNotNull(retrievedChallenge);
            assertArrayEquals(challenge, retrievedChallenge);
            verify(transportPool).getChallenge(context, address);
            verify(transportPool).logon(context, address);
        }

        @Test
        @DisplayName("Should manage multiple transport types")
        void testMultipleTransportTypes() throws Exception {
            // Given
            SmbTransport sharedTransport = mock(SmbTransport.class);
            SmbTransport exclusiveTransport = mock(SmbTransport.class);
            SmbTransport signedTransport = mock(SmbTransport.class);

            when(transportPool.getSmbTransport(context, address, DEFAULT_PORT, false)).thenReturn(sharedTransport);
            when(transportPool.getSmbTransport(context, address, DEFAULT_PORT, true)).thenReturn(exclusiveTransport);
            when(transportPool.getSmbTransport(context, address, DEFAULT_PORT, false, true)).thenReturn(signedTransport);

            // When
            SmbTransport shared = transportPool.getSmbTransport(context, address, DEFAULT_PORT, false);
            SmbTransport exclusive = transportPool.getSmbTransport(context, address, DEFAULT_PORT, true);
            SmbTransport signed = transportPool.getSmbTransport(context, address, DEFAULT_PORT, false, true);

            // Then
            assertEquals(sharedTransport, shared);
            assertEquals(exclusiveTransport, exclusive);
            assertEquals(signedTransport, signed);
            verify(transportPool).getSmbTransport(context, address, DEFAULT_PORT, false);
            verify(transportPool).getSmbTransport(context, address, DEFAULT_PORT, true);
            verify(transportPool).getSmbTransport(context, address, DEFAULT_PORT, false, true);
        }
    }
}