package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
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

import org.junit.jupiter.api.Test;

/**
 * Security-focused test cases for BufferCache to verify buffer overflow protection.
 */
public class BufferCacheSecurityTest {

    /**
     * Test that buffer allocation validates size to prevent overflow.
     */
    @Test
    public void testBufferSizeValidation() {
        // When - Get a buffer
        byte[] buffer = BufferCache.getBuffer();

        // Then - Buffer should have expected size
        assertNotNull(buffer, "Buffer should not be null");
        assertEquals(SmbComTransaction.TRANSACTION_BUF_SIZE, buffer.length, "Buffer should have TRANSACTION_BUF_SIZE");

        // The validation in getBuffer() ensures size is within bounds (0 < size <= 1MB)
        assertTrue(buffer.length > 0, "Buffer size should be positive");
        assertTrue(buffer.length <= 0x100000, "Buffer size should not exceed 1MB");
    }

    /**
     * Test that releaseBuffer validates buffer before accepting it.
     */
    @Test
    public void testReleaseBufferValidation() {
        // Given - Various invalid buffers
        byte[] nullBuffer = null;
        byte[] wrongSizeBuffer = new byte[100]; // Wrong size
        byte[] correctBuffer = new byte[SmbComTransaction.TRANSACTION_BUF_SIZE];

        // When/Then - Should handle invalid buffers gracefully
        assertDoesNotThrow(() -> {
            BufferCache.releaseBuffer(nullBuffer); // Should ignore null
            BufferCache.releaseBuffer(wrongSizeBuffer); // Should ignore wrong size
            BufferCache.releaseBuffer(correctBuffer); // Should accept correct size
        });
    }

    /**
     * Test concurrent buffer allocation and release for thread safety.
     */
    @Test
    public void testConcurrentBufferOperations() throws Exception {
        // Given
        int threadCount = 10;
        int opsPerThread = 100;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch endLatch = new CountDownLatch(threadCount);
        AtomicInteger successCount = new AtomicInteger(0);
        List<Exception> exceptions = new ArrayList<>();

        // When - Multiple threads get and release buffers
        for (int t = 0; t < threadCount; t++) {
            executor.submit(() -> {
                try {
                    startLatch.await();

                    for (int i = 0; i < opsPerThread; i++) {
                        // Get buffer
                        byte[] buffer = BufferCache.getBuffer();
                        assertNotNull(buffer, "Buffer should not be null");
                        assertEquals(SmbComTransaction.TRANSACTION_BUF_SIZE, buffer.length, "Buffer should have correct size");

                        // Simulate some work
                        buffer[0] = (byte) i;

                        // Release buffer
                        BufferCache.releaseBuffer(buffer);
                        successCount.incrementAndGet();
                    }
                } catch (Exception e) {
                    synchronized (exceptions) {
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

        // Then - All operations should succeed
        assertTrue(exceptions.isEmpty(), "No exceptions should occur");
        assertEquals(threadCount * opsPerThread, successCount.get(), "All operations should succeed");
    }

    /**
     * Test that buffer cache handles allocation when cache is full.
     */
    @Test
    public void testBufferAllocationWhenCacheFull() {
        // Given - Allocate many buffers to potentially fill the cache
        List<byte[]> buffers = new ArrayList<>();

        // Allocate more buffers than cache can hold
        for (int i = 0; i < 20; i++) {
            byte[] buffer = BufferCache.getBuffer();
            assertNotNull(buffer, "Buffer should not be null even when cache is full");
            assertEquals(SmbComTransaction.TRANSACTION_BUF_SIZE, buffer.length, "Buffer should have correct size");
            buffers.add(buffer);
        }

        // When - Release all buffers back
        for (byte[] buffer : buffers) {
            BufferCache.releaseBuffer(buffer);
        }

        // Then - Should be able to get buffers again
        byte[] newBuffer = BufferCache.getBuffer();
        assertNotNull(newBuffer, "Should be able to get buffer after release");
        assertEquals(SmbComTransaction.TRANSACTION_BUF_SIZE, newBuffer.length, "Buffer should have correct size");
    }

    /**
     * Test that invalid buffer sizes are rejected during release.
     */
    @Test
    public void testInvalidBufferSizeRejection() {
        // Given - Buffers with various invalid sizes
        byte[] tooSmall = new byte[1024];
        byte[] tooLarge = new byte[SmbComTransaction.TRANSACTION_BUF_SIZE + 1];
        byte[] empty = new byte[0];

        // When - Try to release invalid buffers
        assertDoesNotThrow(() -> {
            BufferCache.releaseBuffer(tooSmall);
            BufferCache.releaseBuffer(tooLarge);
            BufferCache.releaseBuffer(empty);
        });

        // Then - Invalid buffers should be silently ignored
        // Get a new buffer to verify cache still works
        byte[] validBuffer = BufferCache.getBuffer();
        assertNotNull(validBuffer, "Cache should still work after invalid releases");
        assertEquals(SmbComTransaction.TRANSACTION_BUF_SIZE, validBuffer.length, "Buffer should have correct size");
    }

    /**
     * Test buffer reuse from cache.
     */
    @Test
    public void testBufferReuse() {
        // Given - Get and release a buffer with specific content
        byte[] buffer1 = BufferCache.getBuffer();
        buffer1[0] = (byte) 0xAB;
        buffer1[1] = (byte) 0xCD;
        BufferCache.releaseBuffer(buffer1);

        // When - Get another buffer (might be the same one from cache)
        byte[] buffer2 = BufferCache.getBuffer();

        // Then - Buffer should be valid
        assertNotNull(buffer2, "Reused buffer should not be null");
        assertEquals(SmbComTransaction.TRANSACTION_BUF_SIZE, buffer2.length, "Reused buffer should have correct size");

        // Note: We don't check if content is cleared as that's not a security requirement
        // The important part is that the buffer is valid and has correct size
    }

    /**
     * Test getBuffers method for transaction buffers.
     */
    @Test
    public void testGetBuffersForTransaction() {
        // Given
        SmbComTransaction req = new SmbComTransaction() {
            @Override
            int writeSetupWireFormat(byte[] dst, int dstIndex) {
                return 0;
            }

            @Override
            int writeParametersWireFormat(byte[] dst, int dstIndex) {
                return 0;
            }

            @Override
            int writeDataWireFormat(byte[] dst, int dstIndex) {
                return 0;
            }

            @Override
            int readSetupWireFormat(byte[] buffer, int bufferIndex, int len) {
                return 0;
            }

            @Override
            int readParametersWireFormat(byte[] buffer, int bufferIndex, int len) {
                return 0;
            }

            @Override
            int readDataWireFormat(byte[] buffer, int bufferIndex, int len) {
                return 0;
            }

            @Override
            public String toString() {
                return "TestTransaction";
            }
        };

        SmbComTransactionResponse rsp = new SmbComTransactionResponse() {
            @Override
            int writeSetupWireFormat(byte[] dst, int dstIndex) {
                return 0;
            }

            @Override
            int writeParametersWireFormat(byte[] dst, int dstIndex) {
                return 0;
            }

            @Override
            int writeDataWireFormat(byte[] dst, int dstIndex) {
                return 0;
            }

            @Override
            int readSetupWireFormat(byte[] buffer, int bufferIndex, int len) {
                return 0;
            }

            @Override
            int readParametersWireFormat(byte[] buffer, int bufferIndex, int len) {
                return 0;
            }

            @Override
            int readDataWireFormat(byte[] buffer, int bufferIndex, int len) {
                return 0;
            }

            @Override
            public String toString() {
                return "TestTransactionResponse";
            }
        };

        // When
        BufferCache.getBuffers(req, rsp);

        // Then
        assertNotNull(req.txn_buf, "Request buffer should be allocated");
        assertNotNull(rsp.txn_buf, "Response buffer should be allocated");
        assertEquals(SmbComTransaction.TRANSACTION_BUF_SIZE, req.txn_buf.length, "Request buffer should have correct size");
        assertEquals(SmbComTransaction.TRANSACTION_BUF_SIZE, rsp.txn_buf.length, "Response buffer should have correct size");
    }

}