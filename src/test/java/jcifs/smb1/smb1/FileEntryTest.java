package jcifs.smb1.smb1;

/**
 * Unit tests for {@link FileEntry}. The interface itself has no
 * implementation, so the tests exercise the contract via Mockito mocks.
 * Each method is exercised for normal inputs, extreme or edge cases, and
 * interaction verification.
 */
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(MockitoExtension.class)
@DisplayName("FileEntry interface contract tests")
class FileEntryTest {

    @Test
    @DisplayName("Mock returns configured values")
    void mockReturnsConfiguredValues() {
        FileEntry mock = mock(FileEntry.class);
        when(mock.getName()).thenReturn("test.txt");
        when(mock.getType()).thenReturn(1);
        when(mock.getAttributes()).thenReturn(128);
        when(mock.createTime()).thenReturn(1_500L);
        when(mock.lastModified()).thenReturn(1_800L);
        when(mock.length()).thenReturn(100L);

        assertEquals("test.txt", mock.getName());
        assertEquals(1, mock.getType());
        assertEquals(128, mock.getAttributes());
        assertEquals(1_500L, mock.createTime());
        assertEquals(1_800L, mock.lastModified());
        assertEquals(100L, mock.length());
    }

    @Nested
    @DisplayName("Edge case values")
    class EdgeCases {

        @Test
        @DisplayName("Null name is allowed via mock")
        void nullName() {
            FileEntry mock = mock(FileEntry.class);
            when(mock.getName()).thenReturn(null);
            assertNull(mock.getName());
        }

        @Test
        @DisplayName("Negative length is allowed via mock")
        void negativeLength() {
            FileEntry mock = mock(FileEntry.class);
            when(mock.length()).thenReturn(-10L);
            assertEquals(-10L, mock.length());
        }
    }

    @ParameterizedTest(name = "getType returns {0}")
    @ValueSource(ints = {0, 1, -5, Integer.MAX_VALUE})
    @DisplayName("Parameterized type values")
    void typeParameterized(int type) {
        FileEntry mock = mock(FileEntry.class);
        when(mock.getType()).thenReturn(type);
        assertEquals(type, mock.getType());
    }

    @Test
    @DisplayName("Interaction verification with mock")
    void interactionVerification() {
        FileEntry mock = mock(FileEntry.class);
        when(mock.length()).thenReturn(42L);
        long len = mock.length();
        assertEquals(42L, len);
        verify(mock, times(1)).length();
        verifyNoMoreInteractions(mock);
    }
}

