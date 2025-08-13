package jcifs.smb;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.stream.Stream;

@ExtendWith(MockitoExtension.class)
class FileEntryTest {

    @Mock
    FileEntry mockEntry;

    // Simple fake implementation to exercise the interface without mocks
    private static final class TestFileEntry implements FileEntry {
        private final String name;
        private final int type;
        private final int attributes;
        private final long createTime;
        private final long lastModified;
        private final long lastAccess;
        private final long length;
        private final int fileIndex;

        TestFileEntry(String name, int type, int attributes, long createTime, long lastModified,
                       long lastAccess, long length, int fileIndex) {
            this.name = name;
            this.type = type;
            this.attributes = attributes;
            this.createTime = createTime;
            this.lastModified = lastModified;
            this.lastAccess = lastAccess;
            this.length = length;
            this.fileIndex = fileIndex;
        }

        @Override
        public String getName() { return name; }

        @Override
        public int getType() { return type; }

        @Override
        public int getAttributes() { return attributes; }

        @Override
        public long createTime() { return createTime; }

        @Override
        public long lastModified() { return lastModified; }

        @Override
        public long lastAccess() { return lastAccess; }

        @Override
        public long length() { return length; }

        @Override
        public int getFileIndex() { return fileIndex; }
    }

    // Functional helpers for concise parameterized tests
    private interface IntGetter { int apply(FileEntry e); }
    private interface LongGetter { long apply(FileEntry e); }

    // --- Mockito-based interaction tests ---

    @Test
    @DisplayName("Mocked FileEntry returns stubbed values and verifies interactions")
    void mockedEntry_happyPath_and_interactions() {
        // Arrange: stub all methods with representative values
        when(mockEntry.getName()).thenReturn("file.txt");
        when(mockEntry.getType()).thenReturn(1);
        when(mockEntry.getAttributes()).thenReturn(0x20);
        when(mockEntry.createTime()).thenReturn(100L);
        when(mockEntry.lastModified()).thenReturn(200L);
        when(mockEntry.lastAccess()).thenReturn(300L);
        when(mockEntry.length()).thenReturn(12345L);

        // Act: call methods, some multiple times
        String name = mockEntry.getName();
        int type1 = mockEntry.getType();
        int type2 = mockEntry.getType(); // called twice for interaction verification
        int attributes = mockEntry.getAttributes();
        long createTime = mockEntry.createTime();
        long lastModified = mockEntry.lastModified();
        long lastAccess = mockEntry.lastAccess();
        long size = mockEntry.length();

        // Assert: values and interactions
        assertEquals("file.txt", name, "getName should return stubbed value");
        assertEquals(1, type1);
        assertEquals(1, type2);
        assertEquals(0x20, attributes);
        assertEquals(100L, createTime);
        assertEquals(200L, lastModified);
        assertEquals(300L, lastAccess);
        assertEquals(12345L, size);

        // Verify precise interactions
        verify(mockEntry, times(1)).getName();
        verify(mockEntry, times(2)).getType();
        verify(mockEntry, times(1)).getAttributes();
        verify(mockEntry, times(1)).createTime();
        verify(mockEntry, times(1)).lastModified();
        verify(mockEntry, times(1)).lastAccess();
        verify(mockEntry, times(1)).length();
        verify(mockEntry, never()).getFileIndex();

        // Verify order among a subset of calls
        InOrder inOrder = inOrder(mockEntry);
        inOrder.verify(mockEntry).getName();
        inOrder.verify(mockEntry, times(2)).getType();
    }

    @Test
    @DisplayName("Mock without interactions reports none")
    void mock_noInteractions() {
        // Arrange/Act: do nothing
        // Assert: verify no interactions
        verifyNoInteractions(mockEntry);
    }

    // --- Fake implementation tests (happy path and edge cases) ---

    @Test
    @DisplayName("Fake implementation returns provided values (happy path)")
    void fakeImplementation_happyPath() {
        // Arrange
        FileEntry e = new TestFileEntry("doc.pdf", 2, 0x10, 10L, 20L, 30L, 4096L, 3);

        // Act & Assert: getters return exactly what was provided
        assertAll(
            () -> assertEquals("doc.pdf", e.getName()),
            () -> assertEquals(2, e.getType()),
            () -> assertEquals(0x10, e.getAttributes()),
            () -> assertEquals(10L, e.createTime()),
            () -> assertEquals(20L, e.lastModified()),
            () -> assertEquals(30L, e.lastAccess()),
            () -> assertEquals(4096L, e.length()),
            () -> assertEquals(3, e.getFileIndex())
        );
    }

    // Parameterized tests for String edge cases on getName
    static Stream<Arguments> nameProvider() {
        return Stream.of(
            Arguments.of("", "empty string is allowed"),
            Arguments.of(" ", "single space is preserved"),
            Arguments.of("复杂名.txt", "unicode name is preserved"),
            Arguments.of(null, "null name is passed through")
        );
    }

    @ParameterizedTest(name = "getName returns as-set: [{0}] - {1}")
    @MethodSource("nameProvider")
    void name_edgeCases(String name, String caseDesc) {
        // Arrange
        FileEntry e = new TestFileEntry(name, 0, 0, 0L, 0L, 0L, 0L, 0);
        // Act
        String actual = e.getName();
        // Assert
        assertEquals(name, actual);
    }

    // Parameterized tests for numeric getters with edge values
    static Stream<Arguments> intGetterProvider() {
        return Stream.of(
            Arguments.of((IntGetter) FileEntry::getType, -1, "negative type"),
            Arguments.of((IntGetter) FileEntry::getType, 0, "zero type"),
            Arguments.of((IntGetter) FileEntry::getType, Integer.MAX_VALUE, "max type"),

            Arguments.of((IntGetter) FileEntry::getAttributes, 0, "no attributes"),
            Arguments.of((IntGetter) FileEntry::getAttributes, 0xFFFF, "many attributes"),

            Arguments.of((IntGetter) FileEntry::getFileIndex, -5, "negative index"),
            Arguments.of((IntGetter) FileEntry::getFileIndex, 0, "zero index")
        );
    }

    @ParameterizedTest(name = "Int getter {2} returns {1}")
    @MethodSource("intGetterProvider")
    void intGetters_edgeCases(IntGetter getter, int value, String label) {
        // Arrange
        FileEntry e = new TestFileEntry("n", value, value, 0L, 0L, 0L, 0L, value);
        // Act
        int actual = getter.apply(e);
        // Assert
        assertEquals(value, actual, label);
    }

    static Stream<Arguments> longGetterProvider() {
        return Stream.of(
            Arguments.of((LongGetter) FileEntry::createTime, -1L, "negative createTime"),
            Arguments.of((LongGetter) FileEntry::createTime, 0L, "zero createTime"),
            Arguments.of((LongGetter) FileEntry::createTime, Long.MAX_VALUE, "max createTime"),

            Arguments.of((LongGetter) FileEntry::lastModified, -2L, "negative lastModified"),
            Arguments.of((LongGetter) FileEntry::lastModified, 42L, "positive lastModified"),

            Arguments.of((LongGetter) FileEntry::lastAccess, 0L, "zero lastAccess"),
            Arguments.of((LongGetter) FileEntry::lastAccess, Long.MIN_VALUE, "min lastAccess"),

            Arguments.of((LongGetter) FileEntry::length, -100L, "negative length"),
            Arguments.of((LongGetter) FileEntry::length, 0L, "zero length"),
            Arguments.of((LongGetter) FileEntry::length, 1L, "small length")
        );
    }

    @ParameterizedTest(name = "Long getter {2} returns {1}")
    @MethodSource("longGetterProvider")
    void longGetters_edgeCases(LongGetter getter, long value, String label) {
        // Arrange
        FileEntry e = new TestFileEntry("n", 0, 0, value, value, value, value, 0);
        // Act
        long actual = getter.apply(e);
        // Assert
        assertEquals(value, actual, label);
    }

    @Test
    @DisplayName("Calling a method on null reference throws NPE")
    void nullReference_throwsNPE() {
        // Arrange
        FileEntry e = null;
        // Act & Assert: demonstrate invalid usage results in NPE
        assertThrows(NullPointerException.class, () -> e.getName());
    }

    @Nested
    @DisplayName("Mockito stubbing for edge cases")
    class MockitoEdgeCases {
        @Test
        @DisplayName("getName can return null and empty strings via mock")
        void mock_nameEdgeValues() {
            // Arrange
            when(mockEntry.getName()).thenReturn(null, "", " ");

            // Act & Assert
            assertNull(mockEntry.getName(), "first call returns null");
            assertEquals("", mockEntry.getName(), "second call returns empty");
            assertEquals(" ", mockEntry.getName(), "third call returns space");

            verify(mockEntry, times(3)).getName();
        }
    }
}
