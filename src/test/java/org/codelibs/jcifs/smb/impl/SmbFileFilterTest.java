package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SmbFileFilterTest {

    @Mock
    private SmbFile smbFile;

    // Provides file names and whether a simple name-based filter should accept them
    private static Stream<Arguments> nameCases() {
        return Stream.of(Arguments.of("readme.txt", true), Arguments.of("notes.log", false), Arguments.of("", false),
                Arguments.of(null, false));
    }

    @Test
    @DisplayName("accept: returns true for directories; verifies isDirectory is invoked")
    void accept_returnsTrueForDirectory_andVerifiesInteraction() throws Exception {
        // Arrange: filter that accepts directories only
        SmbFileFilter filter = f -> f.isDirectory();
        when(smbFile.isDirectory()).thenReturn(true);

        // Act
        boolean result = filter.accept(smbFile);

        // Assert
        assertTrue(result, "Directory should be accepted");
        verify(smbFile, times(1)).isDirectory();
        verify(smbFile, never()).getName();
        verifyNoMoreInteractions(smbFile);
    }

    @Test
    @DisplayName("accept: returns false for non-directories")
    void accept_returnsFalseForNonDirectory() throws Exception {
        // Arrange
        SmbFileFilter filter = f -> f.isDirectory();
        when(smbFile.isDirectory()).thenReturn(false);

        // Act
        boolean result = filter.accept(smbFile);

        // Assert
        assertFalse(result, "Non-directory should be rejected");
        verify(smbFile, times(1)).isDirectory();
        verifyNoMoreInteractions(smbFile);
    }

    @ParameterizedTest(name = "getName='{0}' -> accepted={1}")
    @MethodSource("nameCases")
    @DisplayName("accept: name-based filter handles normal, empty, and null names")
    void accept_nameBasedFilter_handlesEdgeNames(String name, boolean expected) throws Exception {
        // Arrange: filter that accepts non-empty names ending with .txt
        SmbFileFilter filter = f -> {
            String n = f.getName();
            return n != null && !n.isEmpty() && n.endsWith(".txt");
        };
        when(smbFile.getName()).thenReturn(name);

        // Act
        boolean result = filter.accept(smbFile);

        // Assert
        assertEquals(expected, result);
        verify(smbFile, times(1)).getName();
        verifyNoMoreInteractions(smbFile);
    }

    @Test
    @DisplayName("accept: length-based filter evaluates negative/zero/positive sizes")
    void accept_lengthBasedFilter_handlesNumericEdges() throws Exception {
        // Arrange: filter that accepts only strictly positive length
        SmbFileFilter filter = f -> f.length() > 0;

        // negative size -> reject
        when(smbFile.length()).thenReturn(-1L);
        assertFalse(filter.accept(smbFile), "Negative size should be rejected");
        verify(smbFile, times(1)).length();

        // zero size -> reject
        reset(smbFile);
        when(smbFile.length()).thenReturn(0L);
        assertFalse(filter.accept(smbFile), "Zero size should be rejected");
        verify(smbFile, times(1)).length();

        // positive size -> accept
        reset(smbFile);
        when(smbFile.length()).thenReturn(42L);
        assertTrue(filter.accept(smbFile), "Positive size should be accepted");
        verify(smbFile, times(1)).length();
        verifyNoMoreInteractions(smbFile);
    }

    @Test
    @DisplayName("accept: propagates SmbException thrown by dependency")
    void accept_propagatesSmbException() throws Exception {
        // Arrange: filter delegates to isDirectory which may throw SmbException
        SmbFileFilter filter = f -> f.isDirectory();
        SmbException boom = new SmbException("io error");
        when(smbFile.isDirectory()).thenThrow(boom);

        // Act + Assert
        SmbException thrown = assertThrows(SmbException.class, () -> filter.accept(smbFile));
        assertEquals("io error", thrown.getMessage());
        verify(smbFile, times(1)).isDirectory();
        verifyNoMoreInteractions(smbFile);
    }

    @Test
    @DisplayName("accept: rejects null input with meaningful NullPointerException")
    void accept_rejectsNullInput() {
        // Arrange: defensive filter that validates input
        SmbFileFilter filter = f -> {
            if (f == null) {
                throw new NullPointerException("file must not be null");
            }
            return true; // not reached in this test
        };

        // Act + Assert
        NullPointerException npe = assertThrows(NullPointerException.class, () -> filter.accept(null));
        assertEquals("file must not be null", npe.getMessage());
    }
}
