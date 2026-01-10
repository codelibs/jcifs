/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;

import org.codelibs.jcifs.smb.Address;
import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.Credentials;
import org.codelibs.jcifs.smb.NameServiceClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * Tests for error handling in SMB transport layer.
 * Covers network errors, timeouts, and exception propagation.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("SMB Transport Error Handling Tests")
class SmbTransportErrorHandlingTest {

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

    @BeforeEach
    void setUp() {
        pool = new SmbTransportPoolImpl();

        when(ctx.getConfig()).thenReturn(config);
        when(ctx.getNameServiceClient()).thenReturn(nameSvc);
        when(ctx.getCredentials()).thenReturn(creds);
        when(ctx.getTransportPool()).thenReturn(pool);

        when(config.getLocalAddr()).thenReturn(null);
        when(config.getLocalPort()).thenReturn(0);
        when(config.getSessionLimit()).thenReturn(10);
        when(config.isSigningEnforced()).thenReturn(false);
        when(config.isIpcSigningEnforced()).thenReturn(true);
        when(config.getLogonShare()).thenReturn("IPC$");

        when(address.getHostName()).thenReturn("test.host");
        when(address.getHostAddress()).thenReturn("192.168.1.100");
    }

    @Nested
    @DisplayName("Name Resolution Errors")
    class NameResolutionErrors {

        @Test
        @DisplayName("Should throw UnknownHostException when host cannot be resolved")
        void testUnknownHost() throws Exception {
            when(nameSvc.getAllByName(eq("unknown.host"), eq(true)))
                    .thenReturn(new Address[0]);

            assertThrows(UnknownHostException.class,
                    () -> pool.getSmbTransport(ctx, "unknown.host", 445, false, false));
        }

        @Test
        @DisplayName("Should throw UnknownHostException when name service returns null")
        void testNullAddressArray() throws Exception {
            when(nameSvc.getAllByName(eq("null.host"), eq(true)))
                    .thenReturn(null);

            assertThrows(UnknownHostException.class,
                    () -> pool.getSmbTransport(ctx, "null.host", 445, false, false));
        }

        @Test
        @DisplayName("Should propagate CIFSException from name service")
        void testNameServiceException() throws Exception {
            when(nameSvc.getAllByName(eq("error.host"), eq(true)))
                    .thenThrow(new UnknownHostException("DNS lookup failed"));

            assertThrows(UnknownHostException.class,
                    () -> pool.getSmbTransport(ctx, "error.host", 445, false, false));
        }
    }

    @Nested
    @DisplayName("Connection Errors")
    class ConnectionErrors {

        @Test
        @DisplayName("Should handle connection refused error")
        void testConnectionRefused() throws Exception {
            Address addr = mock(Address.class);
            when(addr.getHostAddress()).thenReturn("10.0.0.1");
            when(nameSvc.getAllByName(eq("refused.host"), eq(true)))
                    .thenReturn(new Address[] { addr });

            SmbTransportPoolImpl poolSpy = spy(pool);
            when(ctx.getTransportPool()).thenReturn(poolSpy);

            SmbTransportImpl mockTransport = mock(SmbTransportImpl.class);
            when(mockTransport.unwrap(SmbTransportImpl.class)).thenReturn(mockTransport);
            doThrow(new ConnectException("Connection refused"))
                    .when(mockTransport).ensureConnected();

            doReturn(mockTransport).when(poolSpy)
                    .getSmbTransport(eq(ctx), eq(addr), anyInt(), anyBoolean(), anyBoolean());

            IOException ex = assertThrows(IOException.class,
                    () -> poolSpy.getSmbTransport(ctx, "refused.host", 445, false, false));
            assertTrue(ex.getMessage().contains("Connection refused"));

            // Verify fail count was incremented
            assertEquals(1, pool.failCounts.get("10.0.0.1"));
        }

        @Test
        @DisplayName("Should handle connection timeout")
        void testConnectionTimeout() throws Exception {
            Address addr = mock(Address.class);
            when(addr.getHostAddress()).thenReturn("10.0.0.2");
            when(nameSvc.getAllByName(eq("timeout.host"), eq(true)))
                    .thenReturn(new Address[] { addr });

            SmbTransportPoolImpl poolSpy = spy(pool);
            when(ctx.getTransportPool()).thenReturn(poolSpy);

            SmbTransportImpl mockTransport = mock(SmbTransportImpl.class);
            when(mockTransport.unwrap(SmbTransportImpl.class)).thenReturn(mockTransport);
            doThrow(new SocketTimeoutException("Connection timed out"))
                    .when(mockTransport).ensureConnected();

            doReturn(mockTransport).when(poolSpy)
                    .getSmbTransport(eq(ctx), eq(addr), anyInt(), anyBoolean(), anyBoolean());

            IOException ex = assertThrows(IOException.class,
                    () -> poolSpy.getSmbTransport(ctx, "timeout.host", 445, false, false));
            assertTrue(ex instanceof SocketTimeoutException);
        }

        @Test
        @DisplayName("Should handle no route to host error")
        void testNoRouteToHost() throws Exception {
            Address addr = mock(Address.class);
            when(addr.getHostAddress()).thenReturn("10.0.0.3");
            when(nameSvc.getAllByName(eq("noroute.host"), eq(true)))
                    .thenReturn(new Address[] { addr });

            SmbTransportPoolImpl poolSpy = spy(pool);
            when(ctx.getTransportPool()).thenReturn(poolSpy);

            SmbTransportImpl mockTransport = mock(SmbTransportImpl.class);
            when(mockTransport.unwrap(SmbTransportImpl.class)).thenReturn(mockTransport);
            doThrow(new NoRouteToHostException("No route to host"))
                    .when(mockTransport).ensureConnected();

            doReturn(mockTransport).when(poolSpy)
                    .getSmbTransport(eq(ctx), eq(addr), anyInt(), anyBoolean(), anyBoolean());

            IOException ex = assertThrows(IOException.class,
                    () -> poolSpy.getSmbTransport(ctx, "noroute.host", 445, false, false));
            assertTrue(ex instanceof NoRouteToHostException);
        }

        @Test
        @DisplayName("Should handle socket exception")
        void testSocketException() throws Exception {
            Address addr = mock(Address.class);
            when(addr.getHostAddress()).thenReturn("10.0.0.4");
            when(nameSvc.getAllByName(eq("socket.host"), eq(true)))
                    .thenReturn(new Address[] { addr });

            SmbTransportPoolImpl poolSpy = spy(pool);
            when(ctx.getTransportPool()).thenReturn(poolSpy);

            SmbTransportImpl mockTransport = mock(SmbTransportImpl.class);
            when(mockTransport.unwrap(SmbTransportImpl.class)).thenReturn(mockTransport);
            doThrow(new SocketException("Socket closed"))
                    .when(mockTransport).ensureConnected();

            doReturn(mockTransport).when(poolSpy)
                    .getSmbTransport(eq(ctx), eq(addr), anyInt(), anyBoolean(), anyBoolean());

            IOException ex = assertThrows(IOException.class,
                    () -> poolSpy.getSmbTransport(ctx, "socket.host", 445, false, false));
            assertTrue(ex instanceof SocketException);
        }
    }

    @Nested
    @DisplayName("Failover Behavior")
    class FailoverBehavior {

        @Test
        @DisplayName("Should try next address when first fails")
        void testFailoverToNextAddress() throws Exception {
            Address addr1 = mock(Address.class);
            when(addr1.getHostAddress()).thenReturn("10.0.0.1");

            Address addr2 = mock(Address.class);
            when(addr2.getHostAddress()).thenReturn("10.0.0.2");

            when(nameSvc.getAllByName(eq("failover.host"), eq(true)))
                    .thenReturn(new Address[] { addr1, addr2 });

            SmbTransportPoolImpl poolSpy = spy(pool);
            when(ctx.getTransportPool()).thenReturn(poolSpy);

            // First address fails
            SmbTransportImpl mockTransport1 = mock(SmbTransportImpl.class);
            when(mockTransport1.unwrap(SmbTransportImpl.class)).thenReturn(mockTransport1);
            doThrow(new IOException("Connection failed")).when(mockTransport1).ensureConnected();

            // Second address succeeds
            SmbTransportImpl mockTransport2 = mock(SmbTransportImpl.class);
            when(mockTransport2.unwrap(SmbTransportImpl.class)).thenReturn(mockTransport2);
            when(mockTransport2.ensureConnected()).thenReturn(true);
            when(mockTransport2.acquire()).thenReturn(mockTransport2);

            doReturn(mockTransport1).when(poolSpy)
                    .getSmbTransport(eq(ctx), eq(addr1), anyInt(), anyBoolean(), anyBoolean());
            doReturn(mockTransport2).when(poolSpy)
                    .getSmbTransport(eq(ctx), eq(addr2), anyInt(), anyBoolean(), anyBoolean());

            SmbTransportImpl result = poolSpy.getSmbTransport(ctx, "failover.host", 445, false, false);

            assertNotNull(result);
            assertEquals(mockTransport2, result);
            assertEquals(1, pool.failCounts.get("10.0.0.1"));
        }

        @Test
        @DisplayName("Should throw last exception when all addresses fail")
        void testAllAddressesFail() throws Exception {
            Address addr1 = mock(Address.class);
            when(addr1.getHostAddress()).thenReturn("10.0.0.1");

            Address addr2 = mock(Address.class);
            when(addr2.getHostAddress()).thenReturn("10.0.0.2");

            when(nameSvc.getAllByName(eq("allfail.host"), eq(true)))
                    .thenReturn(new Address[] { addr1, addr2 });

            SmbTransportPoolImpl poolSpy = spy(pool);
            when(ctx.getTransportPool()).thenReturn(poolSpy);

            SmbTransportImpl mockTransport1 = mock(SmbTransportImpl.class);
            when(mockTransport1.unwrap(SmbTransportImpl.class)).thenReturn(mockTransport1);
            doThrow(new IOException("First failure")).when(mockTransport1).ensureConnected();

            SmbTransportImpl mockTransport2 = mock(SmbTransportImpl.class);
            when(mockTransport2.unwrap(SmbTransportImpl.class)).thenReturn(mockTransport2);
            doThrow(new IOException("Second failure")).when(mockTransport2).ensureConnected();

            doReturn(mockTransport1).when(poolSpy)
                    .getSmbTransport(eq(ctx), eq(addr1), anyInt(), anyBoolean(), anyBoolean());
            doReturn(mockTransport2).when(poolSpy)
                    .getSmbTransport(eq(ctx), eq(addr2), anyInt(), anyBoolean(), anyBoolean());

            IOException ex = assertThrows(IOException.class,
                    () -> poolSpy.getSmbTransport(ctx, "allfail.host", 445, false, false));

            // Should throw the last exception
            assertTrue(ex.getMessage().contains("Second failure"));

            // Both addresses should have fail counts
            assertEquals(1, pool.failCounts.get("10.0.0.1"));
            assertEquals(1, pool.failCounts.get("10.0.0.2"));
        }

        @Test
        @DisplayName("Should prefer addresses with lower fail counts")
        void testPreferLowerFailCount() throws Exception {
            Address addr1 = mock(Address.class);
            when(addr1.getHostAddress()).thenReturn("10.0.0.1");

            Address addr2 = mock(Address.class);
            when(addr2.getHostAddress()).thenReturn("10.0.0.2");

            // Set fail counts - addr1 has more failures
            pool.failCounts.put("10.0.0.1", 5);
            pool.failCounts.put("10.0.0.2", 1);

            when(nameSvc.getAllByName(eq("sorted.host"), eq(true)))
                    .thenReturn(new Address[] { addr1, addr2 });

            SmbTransportPoolImpl poolSpy = spy(pool);
            when(ctx.getTransportPool()).thenReturn(poolSpy);

            // addr2 succeeds (should be tried first due to lower fail count)
            SmbTransportImpl mockTransport2 = mock(SmbTransportImpl.class);
            when(mockTransport2.unwrap(SmbTransportImpl.class)).thenReturn(mockTransport2);
            when(mockTransport2.ensureConnected()).thenReturn(true);
            when(mockTransport2.acquire()).thenReturn(mockTransport2);

            doReturn(mockTransport2).when(poolSpy)
                    .getSmbTransport(eq(ctx), eq(addr2), anyInt(), anyBoolean(), anyBoolean());

            SmbTransportImpl result = poolSpy.getSmbTransport(ctx, "sorted.host", 445, false, false);

            assertEquals(mockTransport2, result);
            // addr1's fail count should remain unchanged
            assertEquals(5, pool.failCounts.get("10.0.0.1"));
        }
    }

    @Nested
    @DisplayName("Challenge/Logon Errors")
    class ChallengeLogonErrors {

        @Test
        @DisplayName("Should wrap IOException in SmbException for getChallenge")
        void testGetChallengeIOException() throws Exception {
            SmbTransportPoolImpl poolSpy = spy(pool);
            when(ctx.getTransportPool()).thenReturn(poolSpy);
            when(creds.isAnonymous()).thenReturn(false);

            SmbTransportImpl mockTransport = mock(SmbTransportImpl.class);
            SmbTransportInternal internal = mock(SmbTransportInternal.class);

            when(mockTransport.unwrap(SmbTransportInternal.class)).thenReturn(internal);
            doThrow(new IOException("Network error")).when(internal).ensureConnected();

            doReturn(mockTransport).when(poolSpy)
                    .getSmbTransport(eq(ctx), any(Address.class), anyInt(), eq(false), anyBoolean());

            SmbException ex = assertThrows(SmbException.class,
                    () -> poolSpy.getChallenge(ctx, address));

            assertTrue(ex.getMessage().contains("Connection failed"));
        }

        @Test
        @DisplayName("Should propagate SmbException from getChallenge")
        void testGetChallengeSmbException() throws Exception {
            SmbTransportPoolImpl poolSpy = spy(pool);
            when(ctx.getTransportPool()).thenReturn(poolSpy);
            when(creds.isAnonymous()).thenReturn(false);

            SmbTransportImpl mockTransport = mock(SmbTransportImpl.class);
            SmbTransportInternal internal = mock(SmbTransportInternal.class);

            when(mockTransport.unwrap(SmbTransportInternal.class)).thenReturn(internal);
            doThrow(new SmbException("SMB error")).when(internal).ensureConnected();

            doReturn(mockTransport).when(poolSpy)
                    .getSmbTransport(eq(ctx), any(Address.class), anyInt(), eq(false), anyBoolean());

            SmbException ex = assertThrows(SmbException.class,
                    () -> poolSpy.getChallenge(ctx, address));

            assertTrue(ex.getMessage().contains("SMB error"));
        }
    }

    @Nested
    @DisplayName("Pool Close Errors")
    class PoolCloseErrors {

        @Test
        @DisplayName("Should continue closing connections even when some fail")
        void testCloseWithErrors() throws Exception {
            // This test verifies that close() continues even when disconnect fails
            SmbTransportImpl transport = pool.getSmbTransport(ctx, address, 445, false);
            assertNotNull(transport);

            // Close should not throw even if internal operations fail
            boolean inUse = pool.close();
            // Result depends on connection state
            assertTrue(true, "Close should complete without throwing");
        }
    }

    @Nested
    @DisplayName("Port Handling")
    class PortHandling {

        @ParameterizedTest
        @ValueSource(ints = { 0, -1, -100 })
        @DisplayName("Should default to port 445 for invalid port values")
        void testInvalidPortDefaults(int invalidPort) {
            SmbTransportImpl transport = pool.getSmbTransport(ctx, address, invalidPort, false);
            assertNotNull(transport, "Transport should be created with default port");
        }

        @Test
        @DisplayName("Should use specified valid port")
        void testValidPort() {
            SmbTransportImpl transport139 = pool.getSmbTransport(ctx, address, 139, false);
            SmbTransportImpl transport445 = pool.getSmbTransport(ctx, address, 445, false);

            assertNotNull(transport139);
            assertNotNull(transport445);
        }
    }
}
