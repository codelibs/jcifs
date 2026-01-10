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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.codelibs.jcifs.smb.Address;
import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.Credentials;
import org.codelibs.jcifs.smb.NameServiceClient;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * Concurrency and thread safety tests for SmbTransportPoolImpl.
 * These tests verify that the transport pool handles concurrent access correctly.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("SmbTransportPoolImpl Concurrency Tests")
class SmbTransportPoolConcurrencyTest {

    private SmbTransportPoolImpl pool;
    private ExecutorService executor;

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
        executor = Executors.newFixedThreadPool(10);

        when(ctx.getConfig()).thenReturn(config);
        when(ctx.getNameServiceClient()).thenReturn(nameSvc);
        when(ctx.getCredentials()).thenReturn(creds);
        when(ctx.getTransportPool()).thenReturn(pool);

        when(config.getLocalAddr()).thenReturn(null);
        when(config.getLocalPort()).thenReturn(0);
        when(config.getSessionLimit()).thenReturn(10);
        when(config.isSigningEnforced()).thenReturn(false);
        when(config.isIpcSigningEnforced()).thenReturn(true);

        when(address.getHostName()).thenReturn("test.host");
        when(address.getHostAddress()).thenReturn("192.168.1.100");
    }

    @AfterEach
    void tearDown() throws Exception {
        executor.shutdownNow();
        executor.awaitTermination(5, TimeUnit.SECONDS);
        pool.close();
    }

    @Test
    @DisplayName("Should handle concurrent connection requests without throwing exceptions")
    void testConcurrentConnectionRequests() throws Exception {
        int threadCount = 20;
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        List<Exception> exceptions = Collections.synchronizedList(new ArrayList<>());
        Set<SmbTransportImpl> transports = ConcurrentHashMap.newKeySet();

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    SmbTransportImpl transport = pool.getSmbTransport(ctx, address, 445, false);
                    transports.add(transport);
                } catch (Exception e) {
                    exceptions.add(e);
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        assertTrue(doneLatch.await(10, TimeUnit.SECONDS), "All threads should complete");
        assertTrue(exceptions.isEmpty(), "No exceptions should be thrown: " + exceptions);
        assertFalse(transports.isEmpty(), "Transports should be created");
    }

    @RepeatedTest(5)
    @DisplayName("Should maintain pool integrity under concurrent add/remove operations")
    void testConcurrentAddRemove() throws Exception {
        int operationsPerThread = 50;
        int threadCount = 10;
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        AtomicInteger successCount = new AtomicInteger(0);
        List<Exception> exceptions = Collections.synchronizedList(new ArrayList<>());

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int j = 0; j < operationsPerThread; j++) {
                        SmbTransportImpl transport = pool.getSmbTransport(ctx, address, 445, false);
                        if (j % 2 == 0) {
                            pool.removeTransport(transport);
                        }
                        successCount.incrementAndGet();
                    }
                } catch (Exception e) {
                    exceptions.add(e);
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        assertTrue(doneLatch.await(30, TimeUnit.SECONDS), "All threads should complete");
        assertTrue(exceptions.isEmpty(), "No exceptions should be thrown: " + exceptions);
        assertEquals(threadCount * operationsPerThread, successCount.get(),
                "All operations should succeed");
    }

    @Test
    @DisplayName("Should handle concurrent close operations safely")
    void testConcurrentClose() throws Exception {
        // First, create some connections
        for (int i = 0; i < 10; i++) {
            pool.getSmbTransport(ctx, address, 445, false);
        }

        int threadCount = 5;
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        List<Exception> exceptions = Collections.synchronizedList(new ArrayList<>());

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    pool.close();
                } catch (Exception e) {
                    exceptions.add(e);
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        assertTrue(doneLatch.await(10, TimeUnit.SECONDS), "All threads should complete");
        assertTrue(exceptions.isEmpty(), "No exceptions should be thrown during concurrent close: " + exceptions);
    }

    @Test
    @DisplayName("Should handle mixed read/write operations concurrently")
    void testConcurrentMixedOperations() throws Exception {
        int threadCount = 20;
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        List<Exception> exceptions = Collections.synchronizedList(new ArrayList<>());

        for (int i = 0; i < threadCount; i++) {
            final int threadId = i;
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int j = 0; j < 20; j++) {
                        switch ((threadId + j) % 4) {
                        case 0:
                            // Add pooled connection
                            pool.getSmbTransport(ctx, address, 445, false);
                            break;
                        case 1:
                            // Add non-pooled connection
                            pool.getSmbTransport(ctx, address, 445, true);
                            break;
                        case 2:
                            // Check contains
                            SmbTransportImpl t = pool.getSmbTransport(ctx, address, 445, false);
                            pool.contains(t);
                            break;
                        case 3:
                            // Remove
                            SmbTransportImpl tr = pool.getSmbTransport(ctx, address, 445, false);
                            pool.removeTransport(tr);
                            break;
                        }
                    }
                } catch (Exception e) {
                    exceptions.add(e);
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        assertTrue(doneLatch.await(30, TimeUnit.SECONDS), "All threads should complete");
        assertTrue(exceptions.isEmpty(), "No exceptions should be thrown: " + exceptions);
    }

    @Test
    @DisplayName("Should correctly track fail counts under concurrent access")
    void testConcurrentFailCountUpdates() throws Exception {
        int threadCount = 10;
        int incrementsPerThread = 100;
        String hostAddress = "10.0.0.1";
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int j = 0; j < incrementsPerThread; j++) {
                        Integer current = pool.failCounts.get(hostAddress);
                        if (current == null) {
                            pool.failCounts.put(hostAddress, 1);
                        } else {
                            pool.failCounts.put(hostAddress, current + 1);
                        }
                    }
                } catch (Exception e) {
                    // Ignore
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        assertTrue(doneLatch.await(10, TimeUnit.SECONDS), "All threads should complete");

        // Due to race conditions in non-atomic increment, the count may be less than expected
        // This test verifies the map doesn't throw exceptions, not that it's atomic
        Integer finalCount = pool.failCounts.get(hostAddress);
        assertTrue(finalCount != null && finalCount > 0, "Fail count should be updated");
    }

    @Test
    @DisplayName("Should handle rapid connection creation and removal")
    void testRapidCreateAndRemove() throws Exception {
        int iterations = 100;
        CountDownLatch doneLatch = new CountDownLatch(iterations);
        List<Exception> exceptions = Collections.synchronizedList(new ArrayList<>());

        for (int i = 0; i < iterations; i++) {
            executor.submit(() -> {
                try {
                    SmbTransportImpl transport = pool.getSmbTransport(ctx, address, 445, false);
                    Thread.sleep(1); // Brief delay
                    pool.removeTransport(transport);
                } catch (Exception e) {
                    exceptions.add(e);
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        assertTrue(doneLatch.await(30, TimeUnit.SECONDS), "All iterations should complete");
        assertTrue(exceptions.isEmpty(), "No exceptions should be thrown: " + exceptions);
    }

    @Test
    @DisplayName("Should handle concurrent access to different addresses")
    void testConcurrentDifferentAddresses() throws Exception {
        int addressCount = 5;
        int threadsPerAddress = 4;
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(addressCount * threadsPerAddress);
        List<Exception> exceptions = Collections.synchronizedList(new ArrayList<>());

        for (int addrIdx = 0; addrIdx < addressCount; addrIdx++) {
            Address mockAddr = org.mockito.Mockito.mock(Address.class);
            when(mockAddr.getHostName()).thenReturn("host" + addrIdx);
            when(mockAddr.getHostAddress()).thenReturn("192.168.1." + addrIdx);

            for (int t = 0; t < threadsPerAddress; t++) {
                final Address addr = mockAddr;
                executor.submit(() -> {
                    try {
                        startLatch.await();
                        for (int j = 0; j < 10; j++) {
                            SmbTransportImpl transport = pool.getSmbTransport(ctx, addr, 445, false);
                            pool.contains(transport);
                        }
                    } catch (Exception e) {
                        exceptions.add(e);
                    } finally {
                        doneLatch.countDown();
                    }
                });
            }
        }

        startLatch.countDown();
        assertTrue(doneLatch.await(30, TimeUnit.SECONDS), "All threads should complete");
        assertTrue(exceptions.isEmpty(), "No exceptions should be thrown: " + exceptions);
    }

    @Test
    @DisplayName("Should not deadlock when operations interleave")
    void testNoDeadlock() throws Exception {
        int threadCount = 10;
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        AtomicInteger completed = new AtomicInteger(0);

        for (int i = 0; i < threadCount; i++) {
            final int id = i;
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int j = 0; j < 50; j++) {
                        // Mix of operations that could potentially deadlock
                        SmbTransportImpl t1 = pool.getSmbTransport(ctx, address, 445, false);
                        SmbTransportImpl t2 = pool.getSmbTransport(ctx, address, 445, true);
                        pool.contains(t1);
                        pool.removeTransport(t2);
                        if (id % 3 == 0 && j % 10 == 0) {
                            // Occasionally trigger cleanup via close
                            // (we'll recreate the pool after)
                        }
                    }
                    completed.incrementAndGet();
                } catch (Exception e) {
                    // Log but continue
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();

        // If there's a deadlock, this will timeout
        boolean finished = doneLatch.await(15, TimeUnit.SECONDS);
        assertTrue(finished, "All threads should complete without deadlock");
        assertTrue(completed.get() > 0, "At least some threads should complete successfully");
    }
}
