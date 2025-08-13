package jcifs.internal;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

/**
 * Tests for SmbBasicFileInfo interface.
 * The tests exercise typical, edge, and null scenarios using a simple
 * implementation and a Mockito mock to verify interactions.
 */
@ExtendWith(MockitoExtension.class)
public class SmbBasicFileInfoTest {

    /**
     * Simple concrete implementation used for testing return values.
     */
    private static class TestInfo implements SmbBasicFileInfo {
        private final int attributes;
        private final long createTime;
        private final long lastWriteTime;
        private final long lastAccessTime;
        private final long size;

        TestInfo(int attributes, long createTime, long lastWriteTime, long lastAccessTime, long size) {
            this.attributes = attributes;
            this.createTime = createTime;
            this.lastWriteTime = lastWriteTime;
            this.lastAccessTime = lastAccessTime;
            this.size = size;
        }

        @Override
        public int getAttributes() {
            return attributes;
        }

        @Override
        public long getCreateTime() {
            return createTime;
        }

        @Override
        public long getLastWriteTime() {
            return lastWriteTime;
        }

        @Override
        public long getLastAccessTime() {
            return lastAccessTime;
        }

        @Override
        public long getSize() {
            return size;
        }
    }

    // --- Happy path: direct values are returned as provided ---
    @Test
    void returnsProvidedValues_happyPath() {
        // Arrange
        SmbBasicFileInfo info = new TestInfo(0x20 /* ARCHIVE */, 1_600_000_000_000L, 1_700_000_000_000L, 1_650_000_000_000L, 42L);

        // Act & Assert
        Assertions.assertEquals(0x20, info.getAttributes(), "attributes should match");
        Assertions.assertEquals(1_600_000_000_000L, info.getCreateTime(), "create time should match");
        Assertions.assertEquals(1_700_000_000_000L, info.getLastWriteTime(), "last write should match");
        Assertions.assertEquals(1_650_000_000_000L, info.getLastAccessTime(), "last access should match");
        Assertions.assertEquals(42L, info.getSize(), "size should match");
    }

    // --- Parameterized: edge and boundary values across getters ---
    @ParameterizedTest(name = "attributes={0}, c={1}, w={2}, a={3}, size={4}")
    @MethodSource("valueProvider")
    void returnsValues_forVariousEdges(int attributes, long createTime, long lastWrite, long lastAccess, long size) {
        // Arrange
        SmbBasicFileInfo info = new TestInfo(attributes, createTime, lastWrite, lastAccess, size);

        // Act & Assert
        Assertions.assertEquals(attributes, info.getAttributes());
        Assertions.assertEquals(createTime, info.getCreateTime());
        Assertions.assertEquals(lastWrite, info.getLastWriteTime());
        Assertions.assertEquals(lastAccess, info.getLastAccessTime());
        Assertions.assertEquals(size, info.getSize());
    }

    // Supplies a range of normal and edge case values.
    private static Stream<Arguments> valueProvider() {
        return Stream.of(
                Arguments.of(0, 0L, 0L, 0L, 0L),                      // all zeros
                Arguments.of(1, 1L, 1L, 1L, 1L),                      // ones
                Arguments.of(123, 456L, 789L, 101112L, 131415L),      // arbitrary positives
                Arguments.of(Integer.MAX_VALUE, Long.MAX_VALUE, Long.MIN_VALUE, 999_999_999_999L, -1L), // extremes
                Arguments.of(-1, -2L, -3L, -4L, -5L)                  // negative values
        );
    }

    // --- Mockito interaction: verify each getter is invoked and returns stubbed values ---
    @Test
    void mockitoMock_verifiesGetterInteractions() {
        // Arrange: mock and stub each getter with distinct values
        SmbBasicFileInfo mock = Mockito.mock(SmbBasicFileInfo.class);
        Mockito.when(mock.getAttributes()).thenReturn(7);
        Mockito.when(mock.getCreateTime()).thenReturn(11L);
        Mockito.when(mock.getLastWriteTime()).thenReturn(13L);
        Mockito.when(mock.getLastAccessTime()).thenReturn(17L);
        Mockito.when(mock.getSize()).thenReturn(19L);

        // Act: invoke each method once
        int attributes = mock.getAttributes();
        long c = mock.getCreateTime();
        long w = mock.getLastWriteTime();
        long a = mock.getLastAccessTime();
        long s = mock.getSize();

        // Assert: values and interactions
        Assertions.assertEquals(7, attributes);
        Assertions.assertEquals(11L, c);
        Assertions.assertEquals(13L, w);
        Assertions.assertEquals(17L, a);
        Assertions.assertEquals(19L, s);

        Mockito.verify(mock, Mockito.times(1)).getAttributes();
        Mockito.verify(mock, Mockito.times(1)).getCreateTime();
        Mockito.verify(mock, Mockito.times(1)).getLastWriteTime();
        Mockito.verify(mock, Mockito.times(1)).getLastAccessTime();
        Mockito.verify(mock, Mockito.times(1)).getSize();
        Mockito.verifyNoMoreInteractions(mock);
    }

    // --- Invalid/null usage: calling a method on null should throw NPE ---
    @Test
    void nullReference_throwsNullPointerException() {
        // Arrange
        SmbBasicFileInfo info = null;

        // Act & Assert: attempting to call any method on null should throw NPE
        Assertions.assertThrows(NullPointerException.class, () -> {
            // Intentionally dereference null to validate exception behavior
            // This checks that callers must handle null references defensively
            info.getSize();
        });
    }
}

