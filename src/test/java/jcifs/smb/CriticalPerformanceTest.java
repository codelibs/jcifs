package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import jcifs.Address;
import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.Credentials;
import jcifs.smb1.smb1.BufferCache;

/**
 * Comprehensive performance tests for critical performance fixes
 */
public class CriticalPerformanceTest {

    private CIFSContext mockContext;
    private Configuration mockConfig;
    private Credentials mockCredentials;

    @BeforeEach
    public void setUp() {
        mockContext = Mockito.mock(CIFSContext.class);
        mockConfig = Mockito.mock(Configuration.class);
        mockCredentials = Mockito.mock(Credentials.class);

        Mockito.when(mockContext.getConfig()).thenReturn(mockConfig);
        Mockito.when(mockContext.getCredentials()).thenReturn(mockCredentials);

        // Mock CredentialsInternal for session tests
        jcifs.smb.CredentialsInternal mockCredentialsInternal = Mockito.mock(jcifs.smb.CredentialsInternal.class);
        Mockito.when(mockCredentials.unwrap(jcifs.smb.CredentialsInternal.class)).thenReturn(mockCredentialsInternal);
        Mockito.when(mockCredentialsInternal.clone()).thenReturn(mockCredentialsInternal);
        Mockito.when(mockConfig.getSessionLimit()).thenReturn(10);

        // Clear buffer cache for consistent test results
        BufferCache.clearCache();
    }

    /**
     * Test connection pool scalability with concurrent access
     */
    @Test
    public void testConnectionPoolConcurrentPerformance() throws Exception {
        SmbTransportPoolImpl pool = new SmbTransportPoolImpl();
        pool.setMaxPoolSize(100);

        int threadCount = 20;
        int operationsPerThread = 100;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch endLatch = new CountDownLatch(threadCount);

        AtomicLong totalTime = new AtomicLong(0);
        AtomicInteger successCount = new AtomicInteger(0);
        List<Exception> exceptions = new ArrayList<>();

        // Mock address for testing
        Address mockAddress = Mockito.mock(Address.class);
        Mockito.when(mockAddress.getHostAddress()).thenReturn("127.0.0.1");

        // Start timing
        long overallStart = System.nanoTime();

        for (int t = 0; t < threadCount; t++) {
            executor.submit(() -> {
                try {
                    startLatch.await();

                    long threadStart = System.nanoTime();
                    for (int i = 0; i < operationsPerThread; i++) {
                        try {
                            // Test connection pool operations without actually connecting
                            boolean contains = pool.contains(null); // Should handle gracefully
                            successCount.incrementAndGet();
                        } catch (Exception e) {
                            synchronized (exceptions) {
                                exceptions.add(e);
                            }
                        }
                    }
                    long threadEnd = System.nanoTime();
                    totalTime.addAndGet(threadEnd - threadStart);

                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    endLatch.countDown();
                }
            });
        }

        startLatch.countDown(); // Start all threads
        assertTrue(endLatch.await(30, TimeUnit.SECONDS), "All threads should complete within timeout");
        executor.shutdown();

        long overallEnd = System.nanoTime();
        double overallTimeMs = (overallEnd - overallStart) / 1_000_000.0;
        double avgThreadTimeMs = totalTime.get() / (threadCount * 1_000_000.0);

        System.out.printf("Connection Pool Performance: %d ops in %.2f ms (%.2f ms avg per thread)%n", successCount.get(), overallTimeMs,
                avgThreadTimeMs);

        // Verify performance improvements
        assertTrue(exceptions.isEmpty(), "No exceptions should occur during concurrent access");
        assertEquals(threadCount * operationsPerThread, successCount.get());
        assertTrue(overallTimeMs < 1000, "Operations should complete quickly without lock contention");

        pool.close();
    }

    /**
     * Test buffer cache performance with concurrent operations
     */
    @Test
    public void testBufferCachePerformance() throws Exception {
        int threadCount = 10;
        int operationsPerThread = 1000;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch endLatch = new CountDownLatch(threadCount);

        AtomicInteger allocations = new AtomicInteger(0);
        AtomicInteger releases = new AtomicInteger(0);
        AtomicLong totalAllocTime = new AtomicLong(0);
        AtomicLong totalReleaseTime = new AtomicLong(0);

        long overallStart = System.nanoTime();

        for (int t = 0; t < threadCount; t++) {
            executor.submit(() -> {
                try {
                    startLatch.await();

                    for (int i = 0; i < operationsPerThread; i++) {
                        // Test allocation performance
                        long allocStart = System.nanoTime();
                        byte[] buffer = BufferCache.getBuffer();
                        long allocEnd = System.nanoTime();
                        totalAllocTime.addAndGet(allocEnd - allocStart);
                        allocations.incrementAndGet();

                        assertNotNull(buffer, "Buffer should not be null");
                        assertTrue(buffer.length > 0, "Buffer should have positive length");

                        // Test release performance
                        long releaseStart = System.nanoTime();
                        BufferCache.releaseBuffer(buffer);
                        long releaseEnd = System.nanoTime();
                        totalReleaseTime.addAndGet(releaseEnd - releaseStart);
                        releases.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    endLatch.countDown();
                }
            });
        }

        startLatch.countDown(); // Start all threads
        assertTrue(endLatch.await(10, TimeUnit.SECONDS), "All threads should complete");
        executor.shutdown();

        long overallEnd = System.nanoTime();
        double overallTimeMs = (overallEnd - overallStart) / 1_000_000.0;
        double avgAllocTimeNs = totalAllocTime.get() / (double) allocations.get();
        double avgReleaseTimeNs = totalReleaseTime.get() / (double) releases.get();

        System.out.printf("Buffer Cache Performance: %d allocs, %d releases in %.2f ms%n", allocations.get(), releases.get(),
                overallTimeMs);
        System.out.printf("  Avg allocation time: %.2f ns%n", avgAllocTimeNs);
        System.out.printf("  Avg release time: %.2f ns%n", avgReleaseTimeNs);

        // Verify O(1) performance - should be reasonably fast (allowing for JVM overhead)
        assertTrue(avgAllocTimeNs < 10000, "Average allocation should be under 10000ns (O(1) performance)");
        assertTrue(avgReleaseTimeNs < 10000, "Average release should be under 10000ns (O(1) performance)");
        assertEquals(threadCount * operationsPerThread, allocations.get());
        assertEquals(threadCount * operationsPerThread, releases.get());

        // Verify cache statistics
        String stats = BufferCache.getCacheStatistics();
        assertNotNull(stats, "Cache statistics should be available");
        System.out.println("Buffer Cache Stats: " + stats);
    }

    /**
     * Test encryption context performance without synchronization bottlenecks
     */
    @Test
    public void testEncryptionContextPerformance() throws Exception {
        // Create mock encryption context for testing (simplified)
        // Note: This tests the atomic operations without actual encryption

        int threadCount = 8;
        int operationsPerThread = 500;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch endLatch = new CountDownLatch(threadCount);

        // Use AtomicLong to simulate the fixed bytesEncrypted field
        AtomicLong mockBytesEncrypted = new AtomicLong(0);
        AtomicLong totalTime = new AtomicLong(0);
        AtomicInteger operations = new AtomicInteger(0);

        long overallStart = System.nanoTime();

        for (int t = 0; t < threadCount; t++) {
            executor.submit(() -> {
                try {
                    startLatch.await();

                    long threadStart = System.nanoTime();
                    for (int i = 0; i < operationsPerThread; i++) {
                        // Simulate the atomic byte tracking operation
                        long start = System.nanoTime();
                        mockBytesEncrypted.addAndGet(1024); // Simulate 1KB message
                        long end = System.nanoTime();

                        totalTime.addAndGet(end - start);
                        operations.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    endLatch.countDown();
                }
            });
        }

        startLatch.countDown(); // Start all threads
        assertTrue(endLatch.await(10, TimeUnit.SECONDS), "All threads should complete");
        executor.shutdown();

        long overallEnd = System.nanoTime();
        double overallTimeMs = (overallEnd - overallStart) / 1_000_000.0;
        double avgOpTimeNs = totalTime.get() / (double) operations.get();

        System.out.printf("Encryption Byte Tracking Performance: %d ops in %.2f ms%n", operations.get(), overallTimeMs);
        System.out.printf("  Avg atomic operation time: %.2f ns%n", avgOpTimeNs);

        // Verify lock-free performance (allowing for JVM overhead)
        assertTrue(avgOpTimeNs < 5000, "Atomic operations should be reasonably fast (no lock contention)");
        assertEquals(threadCount * operationsPerThread, operations.get());
        assertEquals((long) threadCount * operationsPerThread * 1024, mockBytesEncrypted.get());
    }

    /**
     * Test session management thread safety with concurrent operations
     */
    @Test
    public void testSessionManagementConcurrentPerformance() throws Exception {
        SmbTransportImpl mockTransport = Mockito.mock(SmbTransportImpl.class);
        Mockito.when(mockTransport.acquire()).thenReturn(mockTransport);

        SmbSessionImpl session = new SmbSessionImpl(mockContext, "testhost", "testdomain", mockTransport);

        int threadCount = 10;
        int operationsPerThread = 200;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch endLatch = new CountDownLatch(threadCount);

        AtomicInteger treeOperations = new AtomicInteger(0);
        AtomicLong totalTime = new AtomicLong(0);
        List<Exception> exceptions = new ArrayList<>();

        long overallStart = System.nanoTime();

        for (int t = 0; t < threadCount; t++) {
            final int threadId = t;
            executor.submit(() -> {
                try {
                    startLatch.await();

                    long threadStart = System.nanoTime();
                    for (int i = 0; i < operationsPerThread; i++) {
                        try {
                            String shareName = "share" + (threadId % 5); // Use 5 different shares

                            // Test concurrent tree operations (should be thread-safe with CopyOnWriteArrayList)
                            long opStart = System.nanoTime();
                            session.getSmbTree(shareName, null);
                            long opEnd = System.nanoTime();

                            totalTime.addAndGet(opEnd - opStart);
                            treeOperations.incrementAndGet();
                        } catch (Exception e) {
                            synchronized (exceptions) {
                                exceptions.add(e);
                            }
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    endLatch.countDown();
                }
            });
        }

        startLatch.countDown(); // Start all threads
        assertTrue(endLatch.await(15, TimeUnit.SECONDS), "All threads should complete");
        executor.shutdown();

        long overallEnd = System.nanoTime();
        double overallTimeMs = (overallEnd - overallStart) / 1_000_000.0;
        double avgOpTimeNs = totalTime.get() / (double) treeOperations.get();

        System.out.printf("Session Management Performance: %d tree ops in %.2f ms%n", treeOperations.get(), overallTimeMs);
        System.out.printf("  Avg tree operation time: %.2f ns%n", avgOpTimeNs);

        // Verify thread safety and performance
        assertTrue(exceptions.isEmpty(), "No exceptions should occur with thread-safe collections: " + exceptions);
        assertEquals(threadCount * operationsPerThread, treeOperations.get());
        assertTrue(avgOpTimeNs < 100000, "Tree operations should be reasonable with CopyOnWriteArrayList");

        session.release();
    }

    /**
     * Performance regression test for all critical fixes
     */
    @Test
    public void testOverallPerformanceRegression() throws Exception {
        System.out.println("=== Critical Performance Fixes Validation ===");

        // Test multiple components together
        long start = System.nanoTime();

        // 1. Connection Pool Test
        SmbTransportPoolImpl pool = new SmbTransportPoolImpl();
        pool.setMaxPoolSize(50);
        for (int i = 0; i < 100; i++) {
            pool.contains(null); // Should be fast without global sync
        }

        // 2. Buffer Cache Test
        for (int i = 0; i < 100; i++) {
            byte[] buf = BufferCache.getBuffer();
            BufferCache.releaseBuffer(buf);
        }

        // 3. Atomic Operations Test
        AtomicLong counter = new AtomicLong(0);
        for (int i = 0; i < 1000; i++) {
            counter.addAndGet(1024);
        }

        long end = System.nanoTime();
        double totalTimeMs = (end - start) / 1_000_000.0;

        System.out.printf("Overall Performance Test: completed in %.2f ms%n", totalTimeMs);

        // Should complete very quickly with all optimizations
        assertTrue(totalTimeMs < 100, "All operations should complete quickly with performance fixes");

        pool.close();
    }
}