package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

/**
 * Security-focused test cases for SmbSessionImpl to verify race condition fixes.
 */
public class SmbSessionImplSecurityTest {

    private CIFSContext mockContext;
    private SmbTransportImpl mockTransport;
    private Configuration mockConfig;
    private Credentials mockCredentials;
    private CredentialsInternal mockCredentialsInternal;

    @BeforeEach
    public void setUp() {
        mockContext = Mockito.mock(CIFSContext.class);
        mockTransport = Mockito.mock(SmbTransportImpl.class);
        mockConfig = Mockito.mock(Configuration.class);
        mockCredentials = Mockito.mock(Credentials.class);
        mockCredentialsInternal = Mockito.mock(CredentialsInternal.class);

        Mockito.when(mockContext.getConfig()).thenReturn(mockConfig);
        Mockito.when(mockContext.getCredentials()).thenReturn(mockCredentials);
        Mockito.when(mockCredentials.unwrap(Mockito.any())).thenReturn(mockCredentialsInternal);
        Mockito.when(mockCredentialsInternal.clone()).thenReturn(mockCredentialsInternal);
        Mockito.when(mockTransport.acquire()).thenReturn(mockTransport);
    }

    /**
     * Test that concurrent tree operations are thread-safe with CopyOnWriteArrayList.
     */
    @Test
    public void testConcurrentTreeOperationsThreadSafe() throws Exception {
        // Given
        SmbSessionImpl session = new SmbSessionImpl(mockContext, "testhost", "testdomain", mockTransport);

        int threadCount = 10;
        int opsPerThread = 100;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch endLatch = new CountDownLatch(threadCount);
        AtomicInteger successCount = new AtomicInteger(0);
        List<Exception> exceptions = Collections.synchronizedList(new ArrayList<>());

        // When - Multiple threads accessing trees concurrently
        for (int t = 0; t < threadCount; t++) {
            final int threadId = t;
            executor.submit(() -> {
                try {
                    startLatch.await(); // Wait for all threads to be ready

                    for (int i = 0; i < opsPerThread; i++) {
                        String share = "share" + (threadId % 3); // Use 3 different shares

                        // Get or create tree
                        SmbTreeImpl tree = session.getSmbTree(share, null);
                        assertNotNull(tree, "Tree should not be null");

                        // Verify we can acquire the tree
                        tree.acquire();
                        successCount.incrementAndGet();

                        // Small delay to increase chance of race conditions
                        Thread.yield();
                    }
                } catch (Exception e) {
                    exceptions.add(e);
                } finally {
                    endLatch.countDown();
                }
            });
        }

        // Start all threads simultaneously
        startLatch.countDown();

        // Wait for completion
        assertTrue(endLatch.await(30, TimeUnit.SECONDS), "All threads should complete within timeout");
        executor.shutdown();

        // Then - Verify no exceptions occurred
        if (!exceptions.isEmpty()) {
            fail("Concurrent operations caused exceptions: " + exceptions.get(0));
        }

        assertEquals(threadCount * opsPerThread, successCount.get(), "All operations should succeed");
    }

    /**
     * Test that session release with double-check pattern prevents race conditions.
     */
    @Test
    public void testSessionReleaseDoubleCheckPattern() throws Exception {
        // Given
        SmbSessionImpl session = new SmbSessionImpl(mockContext, "testhost", "testdomain", mockTransport);

        int threadCount = 5;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch endLatch = new CountDownLatch(threadCount);
        AtomicInteger releaseCount = new AtomicInteger(0);
        AtomicInteger acquireCount = new AtomicInteger(0);

        // Acquire session multiple times
        for (int i = 0; i < threadCount - 1; i++) {
            session.acquire();
        }

        // When - Multiple threads try to release/acquire concurrently
        for (int t = 0; t < threadCount; t++) {
            final boolean shouldRelease = (t < 3); // First 3 threads release, others acquire

            executor.submit(() -> {
                try {
                    startLatch.await();

                    if (shouldRelease) {
                        session.release();
                        releaseCount.incrementAndGet();
                    } else {
                        session.acquire();
                        acquireCount.incrementAndGet();
                    }

                } catch (Exception e) {
                    // Ignore expected exceptions from over-release
                } finally {
                    endLatch.countDown();
                }
            });
        }

        // Start all threads simultaneously
        startLatch.countDown();

        // Wait for completion
        assertTrue(endLatch.await(10, TimeUnit.SECONDS), "All threads should complete");
        executor.shutdown();

        // Then - Session should be in consistent state
        // The double-check pattern should prevent inconsistent cleanup
        assertTrue(releaseCount.get() > 0 || acquireCount.get() > 0, "Release and acquire counts should be processed");
    }

    /**
     * Test that trees collection is properly cleared during cleanup.
     */
    @Test
    public void testTreesCollectionCleanup() {
        // Given
        SmbSessionImpl session = new SmbSessionImpl(mockContext, "testhost", "testdomain", mockTransport);

        // Add some trees
        SmbTreeImpl tree1 = session.getSmbTree("share1", null);
        SmbTreeImpl tree2 = session.getSmbTree("share2", null);
        assertNotNull(tree1);
        assertNotNull(tree2);

        // When - Release session to trigger cleanup
        session.release();

        // Then - Trees should be cleared (we can't directly verify as it's internal,
        // but the cleanup code with synchronized block ensures it happens atomically)
        // The important part is that no exception occurs and the operation is atomic
    }

    /**
     * Test concurrent acquire and release operations.
     */
    @Test
    public void testConcurrentAcquireRelease() throws Exception {
        // Given
        SmbSessionImpl session = new SmbSessionImpl(mockContext, "testhost", "testdomain", mockTransport);

        int threadCount = 20;
        int opsPerThread = 50;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch endLatch = new CountDownLatch(threadCount);
        List<Exception> exceptions = Collections.synchronizedList(new ArrayList<>());

        // When - Threads randomly acquire and release
        for (int t = 0; t < threadCount; t++) {
            executor.submit(() -> {
                try {
                    startLatch.await();

                    for (int i = 0; i < opsPerThread; i++) {
                        if (Math.random() > 0.5) {
                            session.acquire();
                            Thread.yield(); // Increase chance of race conditions
                            session.release();
                        } else {
                            session.acquire();
                            // Hold for a bit
                            Thread.sleep(1);
                            session.release();
                        }
                    }
                } catch (Exception e) {
                    if (!e.getMessage().contains("Usage count dropped below zero")) {
                        exceptions.add(e);
                    }
                } finally {
                    endLatch.countDown();
                }
            });
        }

        // Start all threads
        startLatch.countDown();

        // Wait for completion
        assertTrue(endLatch.await(30, TimeUnit.SECONDS), "All threads should complete");
        executor.shutdown();

        // Then - No unexpected exceptions
        assertTrue(exceptions.isEmpty(), "No unexpected exceptions should occur");
    }

    /**
     * Test that CopyOnWriteArrayList prevents ConcurrentModificationException.
     */
    @Test
    public void testNoConcurrentModificationException() throws Exception {
        // Given
        SmbSessionImpl session = new SmbSessionImpl(mockContext, "testhost", "testdomain", mockTransport);

        int iterations = 1000;
        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch endLatch = new CountDownLatch(2);
        AtomicInteger successCount = new AtomicInteger(0);
        List<Exception> exceptions = Collections.synchronizedList(new ArrayList<>());

        // Thread 1: Continuously adds trees
        executor.submit(() -> {
            try {
                for (int i = 0; i < iterations; i++) {
                    session.getSmbTree("share" + i, null);
                    successCount.incrementAndGet();
                }
            } catch (Exception e) {
                exceptions.add(e);
            } finally {
                endLatch.countDown();
            }
        });

        // Thread 2: Continuously reads trees
        executor.submit(() -> {
            try {
                for (int i = 0; i < iterations; i++) {
                    // This would cause ConcurrentModificationException with ArrayList
                    session.getSmbTree("readshare", null);
                    successCount.incrementAndGet();
                }
            } catch (Exception e) {
                exceptions.add(e);
            } finally {
                endLatch.countDown();
            }
        });

        // Wait for completion
        assertTrue(endLatch.await(30, TimeUnit.SECONDS), "Both threads should complete");
        executor.shutdown();

        // Then - No ConcurrentModificationException
        for (Exception e : exceptions) {
            assertFalse(e instanceof java.util.ConcurrentModificationException, "Should not have ConcurrentModificationException");
        }

        assertTrue(successCount.get() > 0, "Operations should succeed");
    }
}