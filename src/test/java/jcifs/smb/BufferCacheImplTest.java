package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.Configuration;

@ExtendWith(MockitoExtension.class)
class BufferCacheImplTest {

    @Mock
    Configuration cfg;

    // Verifies constructor that accepts Configuration reads the expected values and uses them
    @Test
    @DisplayName("Constructor(Configuration) uses cache size and maximum buffer size from config")
    void constructorUsesConfigurationAndAllocatesWithConfiguredSize() {
        when(cfg.getBufferCacheSize()).thenReturn(2);
        when(cfg.getMaximumBufferSize()).thenReturn(5);

        BufferCacheImpl impl = new BufferCacheImpl(cfg);

        // Verify interactions happen exactly once during construction
        verify(cfg, times(1)).getBufferCacheSize();
        verify(cfg, times(1)).getMaximumBufferSize();
        verifyNoMoreInteractions(cfg);

        // When cache is empty, getBuffer allocates a new buffer with configured size
        byte[] buf = impl.getBuffer();
        assertNotNull(buf, "getBuffer should never return null");
        assertEquals(5, buf.length, "Newly allocated buffer length should match config maximum size");
    }

    // Happy path: get -> release -> get returns same instance, zeroed on release
    @Test
    @DisplayName("Release stores buffer for reuse and zeroes its contents")
    void releaseStoresAndZeroesBuffer() {
        BufferCacheImpl impl = new BufferCacheImpl(2, 10);

        byte[] b = new byte[10];
        // Fill with non-zero to verify zeroing on release
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) (i + 1);
        }

        // Act: release should zero immediately to avoid leaks
        impl.releaseBuffer(b);

        // Assert: original array is zeroed in-place
        for (byte value : b) {
            assertEquals(0, value, "Released buffer must be zeroed");
        }

        // Next get should return the same instance from cache
        byte[] reused = impl.getBuffer();
        assertSame(b, reused, "Buffer should be reused from cache");
        // And it should still be zeroed
        for (byte value : reused) {
            assertEquals(0, value, "Reused buffer must be zeroed");
        }
    }

    // Edge: cache size 0 means nothing is cached; release still zeroes argument
    @Test
    @DisplayName("Cache size 0: release zeroes but does not cache; getBuffer allocates new")
    void zeroSizedCacheDoesNotStore() {
        BufferCacheImpl impl = new BufferCacheImpl(0, 8);
        byte[] supplied = new byte[3];
        supplied[0] = 1;
        supplied[1] = 2;

        // Release must not throw and must zero the supplied array
        assertDoesNotThrow(() -> impl.releaseBuffer(supplied));
        for (byte value : supplied) {
            assertEquals(0, value, "Released buffer must be zeroed even if not cached");
        }

        // Since cache cannot store, getBuffer must create a new buffer of configured size
        byte[] got = impl.getBuffer();
        assertNotNull(got);
        assertEquals(8, got.length, "Allocation uses configured maximum size when cache is empty");
        assertNotSame(supplied, got, "Zero-sized cache must not return the released instance");
    }

    // Edge: releasing null must be a no-op without exceptions
    @Test
    @DisplayName("releaseBuffer(null) is a no-op and does not throw")
    void releaseNullIsNoop() {
        BufferCacheImpl impl = new BufferCacheImpl(1, 4);
        assertDoesNotThrow(() -> impl.releaseBuffer(null));
        // Subsequent get should still work
        assertEquals(4, impl.getBuffer().length);
    }

    // Capacity behavior: when full, additional releases are dropped; only cached buffers are returned
    @Test
    @DisplayName("Cache capacity respected: extra releases dropped; retrieval order by first free slot")
    void cacheCapacityAndRetrievalOrder() {
        BufferCacheImpl impl = new BufferCacheImpl(2, 3);
        byte[] a = new byte[1];
        byte[] c = new byte[2];
        byte[] d = new byte[4];

        impl.releaseBuffer(a); // goes to slot 0
        impl.releaseBuffer(c); // goes to slot 1
        impl.releaseBuffer(d); // dropped (cache full)

        byte[] first = impl.getBuffer(); // should return slot 0 -> a
        byte[] second = impl.getBuffer(); // then slot 1 -> c
        byte[] third = impl.getBuffer(); // cache empty -> new with size 3

        assertSame(a, first, "First get should return first cached buffer");
        assertSame(c, second, "Second get should return second cached buffer");
        assertNotSame(d, third, "Third get should allocate a new buffer (not the dropped one)");
        assertEquals(3, third.length, "Allocated buffer length matches configured maximum size");
    }

    // Parameterized: exercise small variations of cache size for a simple reuse cycle
    @ParameterizedTest
    @ValueSource(ints = { 1, 2 })
    @DisplayName("Parameterized: buffer reuse works for various small cache sizes")
    void reuseWorksForVariousCacheSizes(int cacheSize) {
        BufferCacheImpl impl = new BufferCacheImpl(cacheSize, 6);
        byte[] toRelease = new byte[5];
        toRelease[0] = 42;
        impl.releaseBuffer(toRelease);

        byte[] fromCache = impl.getBuffer();
        assertSame(toRelease, fromCache, "Released buffer should be returned from cache regardless of cache size");
        // Zeroed upon release
        for (byte value : fromCache) {
            assertEquals(0, value);
        }
    }

    // Invalid inputs: negative sizes for constructor arguments
    @Nested
    class InvalidConstruction {
        @Test
        @DisplayName("Negative maxBuffers throws immediately in constructor")
        void negativeMaxBuffersThrows() {
            assertThrows(NegativeArraySizeException.class, () -> new BufferCacheImpl(-1, 10));
        }

        @Test
        @DisplayName("Negative maxSize throws when allocating a new buffer")
        void negativeMaxSizeThrowsOnAllocation() {
            BufferCacheImpl impl = new BufferCacheImpl(0, -7);
            assertThrows(NegativeArraySizeException.class, impl::getBuffer);
        }
    }

    // Heterogeneous buffer sizes: cache should return exactly what was released
    @Test
    @DisplayName("Cache preserves and returns original buffer instances of varying sizes")
    void returnsExactReleasedInstances() {
        BufferCacheImpl impl = new BufferCacheImpl(3, 8);
        byte[] s1 = new byte[2];
        byte[] s2 = new byte[7];

        impl.releaseBuffer(s1);
        impl.releaseBuffer(s2);

        byte[] r1 = impl.getBuffer();
        byte[] r2 = impl.getBuffer();

        // Order is by first free slot (s1 then s2)
        assertSame(s1, r1);
        assertSame(s2, r2);
        assertEquals(2, r1.length);
        assertEquals(7, r2.length);
    }
}
