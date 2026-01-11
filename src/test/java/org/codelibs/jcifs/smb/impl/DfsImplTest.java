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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.Credentials;
import org.codelibs.jcifs.smb.SmbTransportPool;
import org.codelibs.jcifs.smb.internal.dfs.DfsReferralDataImpl;
import org.codelibs.jcifs.smb.internal.dfs.DfsReferralDataInternal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("DfsImpl Tests")
class DfsImplTest {

    private DfsImpl dfsImpl;
    private CIFSContext mockContext;
    private Configuration mockConfig;
    private Credentials mockCredentials;
    private SmbTransportPool mockTransportPool;

    @BeforeEach
    void setUp() throws IOException {
        // Mock the CIFSContext and its dependencies
        mockContext = mock(CIFSContext.class);
        mockConfig = mock(Configuration.class);
        mockCredentials = mock(Credentials.class);
        mockTransportPool = mock(SmbTransportPool.class);

        // Set up mock behaviors
        when(mockContext.getConfig()).thenReturn(mockConfig);
        when(mockContext.getCredentials()).thenReturn(mockCredentials);
        when(mockContext.getTransportPool()).thenReturn(mockTransportPool);
        when(mockConfig.getDfsTtl()).thenReturn(300L);

        // Mock transport to throw IOException - simulating connection failure
        when(mockTransportPool.getSmbTransport(any(CIFSContext.class), anyString(), anyInt(), anyBoolean(), anyBoolean()))
                .thenThrow(new IOException("Connection failed"));

        // Instantiate the class under test
        dfsImpl = new DfsImpl(mockContext);
    }

    // Test for the constructor
    @Test
    void testDfsImplConstructor() {
        // The constructor is called in setUp(), so if no exception is thrown, this test passes.
        assertNotNull(dfsImpl);
    }

    // Tests for isTrustedDomain
    @Test
    void testIsTrustedDomain_DfsDisabled() throws SmbAuthException {
        // Scenario: DFS is disabled in the configuration.
        when(mockConfig.isDfsDisabled()).thenReturn(true);
        assertFalse(dfsImpl.isTrustedDomain(mockContext, "anydomain.com"));
    }

    @Test
    void testIsTrustedDomain_NoUserDomain() throws SmbAuthException {
        // Scenario: The user credentials do not specify a domain.
        when(mockCredentials.getUserDomain()).thenReturn(null);
        assertFalse(dfsImpl.isTrustedDomain(mockContext, "anydomain.com"));
    }

    @Test
    void testIsTrustedDomain_ConnectionFails() throws SmbAuthException {
        // Scenario: Transport connection fails
        when(mockCredentials.getUserDomain()).thenReturn("authdomain.com");
        // When transport fails, it should return false
        assertFalse(dfsImpl.isTrustedDomain(mockContext, "anydomain.com"));
    }

    // Tests for getDc
    @Test
    void testGetDc_DfsDisabled() throws SmbAuthException {
        // Scenario: DFS is disabled.
        when(mockConfig.isDfsDisabled()).thenReturn(true);
        assertNull(dfsImpl.getDc(mockContext, "anydomain.com"));
    }

    @Test
    void testGetDc_ConnectionFails() throws SmbAuthException {
        // Scenario: Transport connection fails when getting DC
        when(mockCredentials.getUserDomain()).thenReturn("authdomain.com");
        // When transport fails to connect, getDc returns null
        assertNull(dfsImpl.getDc(mockContext, "anydomain.com"));
    }

    // Tests for resolve
    @Test
    void testResolve_DfsDisabled() throws SmbAuthException {
        // Scenario: DFS is disabled.
        when(mockConfig.isDfsDisabled()).thenReturn(true);
        assertNull(dfsImpl.resolve(mockContext, "domain", "root", "/path"));
    }

    @Test
    void testResolve_NullRoot() throws SmbAuthException {
        // Scenario: The root is null.
        assertNull(dfsImpl.resolve(mockContext, "domain", null, "/path"));
    }

    @Test
    void testResolve_NullDomain() throws SmbAuthException {
        // Scenario: The domain is null.
        assertNull(dfsImpl.resolve(mockContext, null, "root", "/path"));
    }

    // Tests for cache
    @Test
    void testCache_DfsDisabled() {
        // Scenario: DFS is disabled.
        when(mockConfig.isDfsDisabled()).thenReturn(true);
        DfsReferralDataInternal mockReferral = mock(DfsReferralDataInternal.class);
        // Should not throw any exception and simply return.
        assertDoesNotThrow(() -> dfsImpl.cache(mockContext, "\\\\server\\share\\path", mockReferral));
    }

    @Test
    void testCache_InvalidPath() {
        // Scenario: The UNC path provided is invalid.
        DfsReferralDataInternal mockReferral = mock(DfsReferralDataInternal.class);
        // Should not throw any exception.
        assertDoesNotThrow(() -> dfsImpl.cache(mockContext, "invalidpath", mockReferral));
    }

    @Test
    void testCache_ValidPath() {
        // Scenario: A valid referral is cached.
        DfsReferralDataInternal mockReferral = mock(DfsReferralDataInternal.class);
        when(mockReferral.getPathConsumed()).thenReturn(15); // e.g., "\\\\server\\share".length()
        when(mockReferral.next()).thenReturn(mockReferral); // Simple loop for the do-while
        assertDoesNotThrow(() -> dfsImpl.cache(mockContext, "\\\\server\\share\\path", mockReferral));
    }

    // Additional tests for edge cases and concurrency

    @Nested
    @DisplayName("Strict View Mode Tests")
    class StrictViewModeTests {

        @Test
        @DisplayName("Should propagate SmbAuthException in strict mode for getDc")
        void testStrictModeAuthExceptionForGetDc() throws Exception {
            when(mockConfig.isDfsStrictView()).thenReturn(true);
            when(mockCredentials.getUserDomain()).thenReturn("domain.com");

            SmbTransportImpl mockTransport = mock(SmbTransportImpl.class);
            SmbTransportInternal mockInternal = mock(SmbTransportInternal.class);

            when(mockTransportPool.getSmbTransport(any(CIFSContext.class), anyString(), anyInt(), anyBoolean(), anyBoolean()))
                    .thenReturn(mockTransport);
            when(mockTransport.unwrap(SmbTransportInternal.class)).thenReturn(mockInternal);
            when(mockInternal.getDfsReferrals(any(), anyString(), anyString(), anyString(), anyInt()))
                    .thenThrow(new SmbAuthException("Authentication failed"));

            assertThrows(SmbAuthException.class, () -> dfsImpl.getDc(mockContext, "domain.com"));
        }

        @Test
        @DisplayName("Should not propagate IOException in strict mode")
        void testStrictModeIOExceptionForGetDc() throws Exception {
            when(mockConfig.isDfsStrictView()).thenReturn(true);
            when(mockCredentials.getUserDomain()).thenReturn("domain.com");

            // IOException should be handled, not propagated
            assertNull(dfsImpl.getDc(mockContext, "domain.com"));
        }
    }

    @Nested
    @DisplayName("Resolution Edge Cases")
    class ResolutionEdgeCaseTests {

        @Test
        @DisplayName("Should return null when root is IPC$")
        void testResolveWithIpcShare() throws SmbAuthException {
            assertNull(dfsImpl.resolve(mockContext, "domain", "IPC$", "\\path"));
        }

        @Test
        @DisplayName("Should handle empty domain in credentials")
        void testResolveWithEmptyDomainCredentials() throws SmbAuthException {
            when(mockCredentials.getUserDomain()).thenReturn("");
            assertNull(dfsImpl.resolve(mockContext, "domain", "root", "\\path"));
        }

        @Test
        @DisplayName("Should normalize domain to lowercase")
        void testDomainNormalization() throws SmbAuthException {
            when(mockCredentials.getUserDomain()).thenReturn(null);
            // Should not throw even with uppercase domain
            assertNull(dfsImpl.resolve(mockContext, "DOMAIN.COM", "root", "\\path"));
        }

        @Test
        @DisplayName("Should handle root-only path")
        void testResolveWithRootOnlyPath() throws SmbAuthException {
            when(mockCredentials.getUserDomain()).thenReturn(null);
            assertNull(dfsImpl.resolve(mockContext, "domain", "root", "\\"));
        }
    }

    @Nested
    @DisplayName("Concurrent Access Tests")
    class ConcurrentAccessTests {

        @Test
        @DisplayName("Should handle concurrent cache operations")
        void testConcurrentCacheAccess() throws Exception {
            int threadCount = 10;
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch doneLatch = new CountDownLatch(threadCount);
            List<Exception> exceptions = Collections.synchronizedList(new ArrayList<>());

            for (int i = 0; i < threadCount; i++) {
                final int idx = i;
                new Thread(() -> {
                    try {
                        startLatch.await();
                        DfsReferralDataInternal mockReferral = mock(DfsReferralDataInternal.class);
                        when(mockReferral.getPathConsumed()).thenReturn(20);
                        when(mockReferral.next()).thenReturn(mockReferral);
                        dfsImpl.cache(mockContext, "\\\\server" + idx + "\\share\\path", mockReferral);
                    } catch (Exception e) {
                        exceptions.add(e);
                    } finally {
                        doneLatch.countDown();
                    }
                }).start();
            }

            startLatch.countDown();
            assertTrue(doneLatch.await(10, TimeUnit.SECONDS), "All threads should complete");
            assertTrue(exceptions.isEmpty(), "No exceptions should be thrown: " + exceptions);
        }

        @Test
        @DisplayName("Should handle concurrent resolve operations")
        void testConcurrentResolveAccess() throws Exception {
            when(mockCredentials.getUserDomain()).thenReturn(null);

            int threadCount = 10;
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch doneLatch = new CountDownLatch(threadCount);
            List<Exception> exceptions = Collections.synchronizedList(new ArrayList<>());

            for (int i = 0; i < threadCount; i++) {
                final int idx = i;
                new Thread(() -> {
                    try {
                        startLatch.await();
                        dfsImpl.resolve(mockContext, "domain" + idx, "root", "\\path");
                    } catch (Exception e) {
                        exceptions.add(e);
                    } finally {
                        doneLatch.countDown();
                    }
                }).start();
            }

            startLatch.countDown();
            assertTrue(doneLatch.await(10, TimeUnit.SECONDS), "All threads should complete");
            assertTrue(exceptions.isEmpty(), "No exceptions should be thrown: " + exceptions);
        }

        @Test
        @DisplayName("Should handle concurrent isTrustedDomain operations")
        void testConcurrentIsTrustedDomainAccess() throws Exception {
            when(mockCredentials.getUserDomain()).thenReturn(null);

            int threadCount = 10;
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch doneLatch = new CountDownLatch(threadCount);
            List<Exception> exceptions = Collections.synchronizedList(new ArrayList<>());

            for (int i = 0; i < threadCount; i++) {
                final int idx = i;
                new Thread(() -> {
                    try {
                        startLatch.await();
                        dfsImpl.isTrustedDomain(mockContext, "domain" + idx + ".com");
                    } catch (Exception e) {
                        exceptions.add(e);
                    } finally {
                        doneLatch.countDown();
                    }
                }).start();
            }

            startLatch.countDown();
            assertTrue(doneLatch.await(10, TimeUnit.SECONDS), "All threads should complete");
            assertTrue(exceptions.isEmpty(), "No exceptions should be thrown: " + exceptions);
        }
    }

    @Nested
    @DisplayName("FQDN Conversion Tests")
    class FqdnConversionTests {

        @Test
        @DisplayName("Should handle FQDN conversion setting enabled")
        void testFqdnConversionEnabled() throws SmbAuthException {
            when(mockConfig.isDfsConvertToFQDN()).thenReturn(true);
            when(mockCredentials.getUserDomain()).thenReturn(null);

            // Should not throw with FQDN conversion enabled
            assertNull(dfsImpl.resolve(mockContext, "domain", "root", "\\path"));
        }
    }

    @Nested
    @DisplayName("Cache Path Parsing Tests")
    class CachePathParsingTests {

        @Test
        @DisplayName("Should handle path with single backslash prefix")
        void testCacheWithSingleBackslashPath() {
            DfsReferralDataInternal mockReferral = mock(DfsReferralDataInternal.class);
            when(mockReferral.getPathConsumed()).thenReturn(10);
            when(mockReferral.next()).thenReturn(mockReferral);

            // Single backslash prefix - invalid but should not crash
            assertDoesNotThrow(() -> dfsImpl.cache(mockContext, "\\server", mockReferral));
        }

        @Test
        @DisplayName("Should handle path with no backslashes")
        void testCacheWithNoBackslashes() {
            DfsReferralDataInternal mockReferral = mock(DfsReferralDataInternal.class);

            assertDoesNotThrow(() -> dfsImpl.cache(mockContext, "nobackslashes", mockReferral));
        }

        @Test
        @DisplayName("Should handle null referral data")
        void testCacheWithNullReferral() {
            assertDoesNotThrow(() -> dfsImpl.cache(mockContext, "\\\\server\\share\\path", null));
        }

        @Test
        @DisplayName("Should handle non-DfsReferralDataInternal type")
        void testCacheWithNonInternalReferral() {
            // Create a mock that is not DfsReferralDataInternal
            org.codelibs.jcifs.smb.DfsReferralData mockReferral =
                    mock(org.codelibs.jcifs.smb.DfsReferralData.class);

            // Should handle gracefully - DFS is disabled when referral is wrong type
            assertDoesNotThrow(() -> dfsImpl.cache(mockContext, "\\\\server\\share\\path", mockReferral));
        }
    }
}
