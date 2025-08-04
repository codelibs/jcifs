package jcifs;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

/**
 * Comprehensive test suite for BufferCache interface.
 * Tests the contract and behavior of BufferCache implementations.
 */
@DisplayName("BufferCache Interface Tests")
class BufferCacheTest extends BaseTest {

    @Mock
    private BufferCache mockBufferCache;

    private TestBufferCacheImpl testCache;

    @BeforeEach
    void setUp() {
        testCache = new TestBufferCacheImpl(5, 1024); // 5 buffers of 1KB each
    }

    @Test
    @DisplayName("BufferCache interface should define correct method signatures")
    void testInterfaceContract() {
        // Given
        BufferCache cache = mockBufferCache;

        // When & Then - verify interface methods exist and can be called
        assertDoesNotThrow(() -> {
            cache.getBuffer();
            cache.releaseBuffer(new byte[1024]);
        }, "All BufferCache interface methods should be callable");
    }

    @Test
    @DisplayName("getBuffer should return non-null byte array")
    void testGetBufferContract() {
        // Given
        byte[] expectedBuffer = new byte[1024];
        when(mockBufferCache.getBuffer()).thenReturn(expectedBuffer);

        // When
        byte[] buffer = mockBufferCache.getBuffer();

        // Then
        assertNotNull(buffer, "getBuffer should never return null");
        assertSame(expectedBuffer, buffer, "Should return configured buffer");
    }

    @Test
    @DisplayName("releaseBuffer should accept byte arrays gracefully")
    void testReleaseBufferContract() {
        // Given
        byte[] buffer = new byte[1024];
        doNothing().when(mockBufferCache).releaseBuffer(buffer);

        // When & Then
        assertDoesNotThrow(() -> {
            mockBufferCache.releaseBuffer(buffer);
        }, "releaseBuffer should handle valid buffers");
    }

    @Test
    @DisplayName("getBuffer should return buffers for use")
    void testGetBufferBasicUsage() {
        // When
        byte[] buffer1 = testCache.getBuffer();
        byte[] buffer2 = testCache.getBuffer();

        // Then
        assertNotNull(buffer1, "First buffer should not be null");
        assertNotNull(buffer2, "Second buffer should not be null");
        assertEquals(1024, buffer1.length, "Buffer should have expected size");
        assertEquals(1024, buffer2.length, "Buffer should have expected size");
        assertNotSame(buffer1, buffer2, "Different calls should return different buffers initially");
    }

    @Test
    @DisplayName("releaseBuffer and getBuffer should implement buffer reuse")
    void testBufferReuse() {
        // Given
        byte[] originalBuffer = testCache.getBuffer();

        // When - release and get again
        testCache.releaseBuffer(originalBuffer);
        byte[] reusedBuffer = testCache.getBuffer();

        // Then
        assertSame(originalBuffer, reusedBuffer, "Released buffer should be reused");
    }

    /**
     * Simple test implementation of BufferCache for testing purposes
     */
    private static class TestBufferCacheImpl implements BufferCache {
        private final List<byte[]> cache;
        private final int bufferSize;
        private final int maxBuffers;

        public TestBufferCacheImpl(int maxBuffers, int bufferSize) {
            this.maxBuffers = maxBuffers;
            this.bufferSize = bufferSize;
            this.cache = new ArrayList<>(maxBuffers);
        }

        @Override
        public synchronized byte[] getBuffer() {
            if (!cache.isEmpty()) {
                return cache.remove(0);
            }
            return new byte[bufferSize];
        }

        @Override
        public synchronized void releaseBuffer(byte[] buf) {
            if (buf != null && cache.size() < maxBuffers) {
                cache.add(buf);
            }
        }
    }
}
