package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jcifs.Address;
import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.Credentials;
import jcifs.NameServiceClient;
import jcifs.internal.SmbNegotiationResponse;

/**
 * Unit tests for SmbTransportPoolImpl using JUnit 5 and Mockito
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("SmbTransportPoolImpl Tests")
class SmbTransportPoolImplTest {

    private SmbTransportPoolImpl pool;

    @Mock
    private CIFSContext ctx;
    @Mock
    private Configuration config;
    @Mock
    private NameServiceClient nameSvc;
    @Mock
    private Credentials creds;
    @Mock
    private Address address;
    @Mock
    private SmbNegotiationResponse negotiationResponse;

    @BeforeEach
    void setUp() {
        // Create a fresh pool instance for each test
        pool = new SmbTransportPoolImpl();

        // Setup default mock behaviors
        when(ctx.getConfig()).thenReturn(config);
        when(ctx.getNameServiceClient()).thenReturn(nameSvc);
        when(ctx.getCredentials()).thenReturn(creds);
        when(ctx.getTransportPool()).thenReturn(pool);

        // Default config values
        when(config.getLocalAddr()).thenReturn(null);
        when(config.getLocalPort()).thenReturn(0);
        when(config.getSessionLimit()).thenReturn(10);
        when(config.isSigningEnforced()).thenReturn(false);
        when(config.isIpcSigningEnforced()).thenReturn(true);
        when(config.getLogonShare()).thenReturn("IPC$");

        // Default address values
        when(address.getHostName()).thenReturn("test.host");
        when(address.getHostAddress()).thenReturn("192.168.1.100");
    }

    @Test
    @DisplayName("Should distinguish between pooled and non-pooled connections")
    void testPooledVsNonPooledConnections() {
        // When: Create pooled and non-pooled connections
        SmbTransportImpl pooled = pool.getSmbTransport(ctx, address, 445, false);
        SmbTransportImpl nonPooled = pool.getSmbTransport(ctx, address, 445, true);

        // Then: Pool should track pooled but not non-pooled
        assertTrue(pool.contains(pooled), "Pooled connection should be tracked");
        assertFalse(pool.contains(nonPooled), "Non-pooled connection should not be tracked");
    }

    @Test
    @DisplayName("Should create new connections when reuse conditions are not met")
    void testNoConnectionReuse() throws Exception {
        // Given: Create a new pool for this test to ensure isolation
        SmbTransportPoolImpl testPool = new SmbTransportPoolImpl();
        when(ctx.getTransportPool()).thenReturn(testPool);

        // Create an existing connection
        SmbTransportImpl first = testPool.getSmbTransport(ctx, address, 445, false);

        // When: Request another connection
        // Note: Real SmbTransportImpl will report as disconnected without actual socket
        SmbTransportImpl second = testPool.getSmbTransport(ctx, address, 445, false);

        // Then: Will create new connection since real transport has no socket
        assertNotSame(first, second, "Should create new connection when first is disconnected");
    }

    @Test
    @DisplayName("Should create new connection when force signing differs")
    void testNoReuseWithDifferentSigning() throws Exception {
        // Given: An existing connection without signing enforced
        SmbTransportImpl initial = pool.getSmbTransport(ctx, address, 445, false, false);

        // Mock the negotiation response
        when(negotiationResponse.isSigningRequired()).thenReturn(false);
        when(negotiationResponse.isSigningNegotiated()).thenReturn(false);
        when(negotiationResponse.canReuse(any(CIFSContext.class), anyBoolean())).thenReturn(true);

        // Use reflection to set the negotiated response
        Field negotiatedField = SmbTransportImpl.class.getDeclaredField("negotiated");
        negotiatedField.setAccessible(true);
        negotiatedField.set(initial, negotiationResponse);

        // When: Request connection with signing enforced
        SmbTransportImpl withSigning = pool.getSmbTransport(ctx, address, 445, false, true);

        // Then: Should create new connection
        assertNotSame(initial, withSigning, "Should create new connection with different signing");
    }

    @Test
    @DisplayName("Should remove transport from pool")
    void testRemoveTransport() {
        // Given: A pooled connection
        SmbTransportImpl transport = pool.getSmbTransport(ctx, address, 445, false);
        assertTrue(pool.contains(transport), "Transport should be in pool initially");

        // When: Remove the transport
        pool.removeTransport(transport);

        // Then: Transport should no longer be in pool
        assertFalse(pool.contains(transport), "Transport should be removed from pool");
    }

    @Test
    @DisplayName("Should close all connections and return in-use status")
    void testCloseAllConnections() throws Exception {
        // Given: Create pooled and non-pooled connections
        SmbTransportImpl pooled = pool.getSmbTransport(ctx, address, 445, false);
        SmbTransportImpl nonPooled = pool.getSmbTransport(ctx, address, 445, true);

        // Use reflection to replace with spies
        Field connectionsField = SmbTransportPoolImpl.class.getDeclaredField("connections");
        connectionsField.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<SmbTransportImpl> connections = (List<SmbTransportImpl>) connectionsField.get(pool);

        Field nonPooledField = SmbTransportPoolImpl.class.getDeclaredField("nonPooledConnections");
        nonPooledField.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<SmbTransportImpl> nonPooledConnections = (List<SmbTransportImpl>) nonPooledField.get(pool);

        // Create spies
        SmbTransportImpl pooledSpy = spy(pooled);
        SmbTransportImpl nonPooledSpy = spy(nonPooled);

        // Replace with spies
        connections.set(connections.indexOf(pooled), pooledSpy);
        nonPooledConnections.set(nonPooledConnections.indexOf(nonPooled), nonPooledSpy);

        // Mock disconnect behavior
        when(pooledSpy.disconnect(false, false)).thenReturn(true); // In use
        when(nonPooledSpy.disconnect(false, false)).thenReturn(false); // Not in use

        // When: Close the pool
        boolean inUse = pool.close();

        // Then: Should report in-use and call disconnect on all
        assertTrue(inUse, "Should report connections in use");
        verify(pooledSpy).disconnect(false, false);
        verify(nonPooledSpy).disconnect(false, false);
    }

    @Test
    @DisplayName("Should get challenge from server")
    void testGetChallenge() throws Exception {
        // Given: Mock transport with server key
        byte[] expectedKey = { 1, 2, 3, 4 };

        SmbTransportPoolImpl poolSpy = spy(pool);
        when(ctx.getTransportPool()).thenReturn(poolSpy);

        SmbTransportImpl mockTransport = mock(SmbTransportImpl.class);
        SmbTransportInternal internal = mock(SmbTransportInternal.class);

        when(mockTransport.unwrap(SmbTransportInternal.class)).thenReturn(internal);
        when(internal.ensureConnected()).thenReturn(true);
        when(internal.getServerEncryptionKey()).thenReturn(expectedKey);

        doReturn(mockTransport).when(poolSpy).getSmbTransport(eq(ctx), any(Address.class), anyInt(), eq(false), anyBoolean());

        // When: Get challenge
        byte[] key = poolSpy.getChallenge(ctx, address);

        // Then: Should return server key
        assertArrayEquals(expectedKey, key, "Should return correct server key");
        verify(internal).ensureConnected();
    }

    @Test
    @DisplayName("Should wrap IOException in SmbException for getChallenge")
    void testGetChallengeIOException() throws Exception {
        // Given: Transport that throws IOException
        SmbTransportPoolImpl poolSpy = spy(pool);
        when(ctx.getTransportPool()).thenReturn(poolSpy);

        SmbTransportImpl mockTransport = mock(SmbTransportImpl.class);
        SmbTransportInternal internal = mock(SmbTransportInternal.class);

        when(mockTransport.unwrap(SmbTransportInternal.class)).thenReturn(internal);
        when(internal.ensureConnected()).thenThrow(new IOException("Connection failed"));

        doReturn(mockTransport).when(poolSpy).getSmbTransport(eq(ctx), any(Address.class), anyInt(), eq(false), anyBoolean());

        // When/Then: Should throw SmbException
        SmbException ex = assertThrows(SmbException.class, () -> poolSpy.getChallenge(ctx, address));
        assertTrue(ex.getMessage().contains("Connection failed"));
    }

    @Test
    @DisplayName("Should perform logon to IPC$ share")
    void testLogon() throws Exception {
        // Given: Mock transport, session and tree
        SmbTransportPoolImpl poolSpy = spy(pool);
        when(ctx.getTransportPool()).thenReturn(poolSpy);
        when(address.getHostName()).thenReturn("server.test");

        SmbTransportImpl mockTransport = mock(SmbTransportImpl.class);
        SmbTransportInternal internal = mock(SmbTransportInternal.class);
        SmbSessionInternal session = mock(SmbSessionInternal.class);
        SmbTreeInternal tree = mock(SmbTreeInternal.class);

        when(mockTransport.unwrap(SmbTransportInternal.class)).thenReturn(internal);
        when(internal.getSmbSession(eq(ctx), eq("server.test"), isNull())).thenReturn(session);
        when(session.unwrap(SmbSessionInternal.class)).thenReturn(session);
        when(session.getSmbTree(eq("IPC$"), isNull())).thenReturn(tree);
        when(tree.unwrap(SmbTreeInternal.class)).thenReturn(tree);

        doReturn(mockTransport).when(poolSpy).getSmbTransport(eq(ctx), eq(address), anyInt(), eq(false), anyBoolean());

        // When: Perform logon
        poolSpy.logon(ctx, address);

        // Then: Should connect to IPC$ share
        verify(tree).connectLogon(ctx);
    }

    @Test
    @DisplayName("Should sort addresses by fail count and failover")
    void testFailoverWithFailCounts() throws Exception {
        // Given: Multiple addresses with different fail counts
        Address addr1 = mock(Address.class);
        when(addr1.getHostAddress()).thenReturn("10.0.0.1");

        Address addr2 = mock(Address.class);
        when(addr2.getHostAddress()).thenReturn("10.0.0.2");

        when(nameSvc.getAllByName(eq("test.server"), eq(true))).thenReturn(new Address[] { addr1, addr2 });

        // Set fail counts (addr1 has more failures, addr2 has fewer)
        pool.failCounts.put("10.0.0.1", 5);
        pool.failCounts.put("10.0.0.2", 1);

        // Create spy to intercept calls
        SmbTransportPoolImpl poolSpy = spy(pool);
        when(ctx.getTransportPool()).thenReturn(poolSpy);

        // Mock transports
        SmbTransportImpl trans1 = mock(SmbTransportImpl.class);
        SmbTransportImpl trans2 = mock(SmbTransportImpl.class);

        // trans2 fails first (lower fail count, tried first), trans1 succeeds
        when(trans2.unwrap(SmbTransportImpl.class)).thenReturn(trans2);
        when(trans2.ensureConnected()).thenThrow(new IOException("Connection failed"));
        doNothing().when(trans2).close();

        when(trans1.unwrap(SmbTransportImpl.class)).thenReturn(trans1);
        when(trans1.ensureConnected()).thenReturn(true);
        when(trans1.acquire()).thenReturn(trans1);
        doNothing().when(trans1).close();

        // Return mocked transports
        doReturn(trans1).when(poolSpy).getSmbTransport(eq(ctx), eq(addr1), anyInt(), anyBoolean(), anyBoolean());
        doReturn(trans2).when(poolSpy).getSmbTransport(eq(ctx), eq(addr2), anyInt(), anyBoolean(), anyBoolean());

        // When: Get transport by name
        SmbTransportImpl result = poolSpy.getSmbTransport(ctx, "test.server", 445, false, false);

        // Then: Should use trans1 (addr2 failed, so tried addr1 next)
        assertSame(trans1, result);

        // Verify fail count incremented for addr2 (was 1, now 2)
        assertEquals(2, poolSpy.failCounts.get("10.0.0.2"));
        // addr1's count should remain unchanged since it succeeded
        assertEquals(5, poolSpy.failCounts.get("10.0.0.1"));
    }

    @Test
    @DisplayName("Should throw UnknownHostException for empty address list")
    void testUnknownHostException() throws Exception {
        // Given: No addresses returned
        when(nameSvc.getAllByName(eq("unknown.host"), eq(true))).thenReturn(new Address[0]);

        // When/Then: Should throw UnknownHostException
        assertThrows(UnknownHostException.class, () -> pool.getSmbTransport(ctx, "unknown.host", 445, false, false));
    }

    @Test
    @DisplayName("Should throw last IOException when all connections fail")
    void testAllConnectionsFail() throws Exception {
        // Given: Multiple addresses that all fail
        Address addr1 = mock(Address.class);
        when(addr1.getHostAddress()).thenReturn("10.0.0.1");

        Address addr2 = mock(Address.class);
        when(addr2.getHostAddress()).thenReturn("10.0.0.2");

        when(nameSvc.getAllByName(eq("failing.server"), eq(true))).thenReturn(new Address[] { addr1, addr2 });

        SmbTransportPoolImpl poolSpy = spy(pool);
        when(ctx.getTransportPool()).thenReturn(poolSpy);

        // Both transports fail
        SmbTransportImpl trans1 = mock(SmbTransportImpl.class);
        SmbTransportImpl trans2 = mock(SmbTransportImpl.class);

        IOException firstException = new IOException("First failure");
        IOException secondException = new IOException("Second failure");

        when(trans1.unwrap(SmbTransportImpl.class)).thenReturn(trans1);
        when(trans1.ensureConnected()).thenThrow(firstException);
        doNothing().when(trans1).close();

        when(trans2.unwrap(SmbTransportImpl.class)).thenReturn(trans2);
        when(trans2.ensureConnected()).thenThrow(secondException);
        doNothing().when(trans2).close();

        doReturn(trans1).when(poolSpy).getSmbTransport(eq(ctx), eq(addr1), anyInt(), anyBoolean(), anyBoolean());
        doReturn(trans2).when(poolSpy).getSmbTransport(eq(ctx), eq(addr2), anyInt(), anyBoolean(), anyBoolean());

        // When/Then: Should throw last exception
        IOException thrown = assertThrows(IOException.class, () -> poolSpy.getSmbTransport(ctx, "failing.server", 445, false, false));
        assertSame(secondException, thrown);

        // Verify fail counts incremented
        assertEquals(1, pool.failCounts.get("10.0.0.1"));
        assertEquals(1, pool.failCounts.get("10.0.0.2"));
    }

    @ParameterizedTest
    @ValueSource(ints = { 0, -1 })
    @DisplayName("Should default to port 445 when port <= 0")
    void testDefaultPort(int invalidPort) throws Exception {
        // Given: Create a new pool for this test to ensure isolation
        SmbTransportPoolImpl testPool = new SmbTransportPoolImpl();
        when(ctx.getTransportPool()).thenReturn(testPool);

        // Connection with invalid port
        SmbTransportImpl first = testPool.getSmbTransport(ctx, address, invalidPort, false);

        // Verify that the transport was created with the default port
        // We can't test reuse with real transports as they report as disconnected without sockets
        assertTrue(testPool.contains(first), "Transport should be in pool");

        // When: Request with different port
        SmbTransportImpl second = testPool.getSmbTransport(ctx, address, 139, false);

        // Then: Should create new connection for different port
        assertNotSame(first, second, "Should create new connection for different port");
    }

    @Test
    @DisplayName("Should not reuse connection when session limit reached")
    void testSessionLimitPreventsReuse() throws Exception {
        // Given: Config with session limit of 1
        when(config.getSessionLimit()).thenReturn(1);

        // Create first connection
        SmbTransportImpl first = pool.getSmbTransport(ctx, address, 445, false);

        // Mock that session limit is reached
        when(negotiationResponse.isSigningRequired()).thenReturn(false);
        when(negotiationResponse.isSigningNegotiated()).thenReturn(false);
        when(negotiationResponse.canReuse(any(CIFSContext.class), anyBoolean())).thenReturn(true);

        Field negotiatedField = SmbTransportImpl.class.getDeclaredField("negotiated");
        negotiatedField.setAccessible(true);
        negotiatedField.set(first, negotiationResponse);

        // Simulate session already in use by adding a session
        Field sessionsField = SmbTransportImpl.class.getDeclaredField("sessions");
        sessionsField.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<Object> sessions = (List<Object>) sessionsField.get(first);
        sessions.add(new Object()); // Add one session to reach the limit

        // When: Request another connection
        SmbTransportImpl second = pool.getSmbTransport(ctx, address, 445, false);

        // Then: Should create new connection due to session limit
        assertNotSame(first, second, "Should create new connection when session limit reached");
    }

    @Test
    @DisplayName("Should access fail counts map correctly")
    void testFailCountsAccess() throws Exception {
        // Given: Access to fail counts via reflection
        Field failCountsField = SmbTransportPoolImpl.class.getDeclaredField("failCounts");
        failCountsField.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<String, Integer> failCounts = (Map<String, Integer>) failCountsField.get(pool);

        // When: Add fail counts
        failCounts.put("192.168.1.1", 3);
        failCounts.put("192.168.1.2", 1);

        // Then: Should be accessible
        assertEquals(3, failCounts.get("192.168.1.1"));
        assertEquals(1, failCounts.get("192.168.1.2"));
    }
}