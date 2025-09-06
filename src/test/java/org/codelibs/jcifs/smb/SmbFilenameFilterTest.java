package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests for SmbFilenameFilter interface behaviors via simple implementations.
 * Each test creates a concrete filter to validate expected contract semantics
 * including normal operation, null handling, edge cases, and exception flow.
 */
@ExtendWith(MockitoExtension.class)
class SmbFilenameFilterTest {

    @Mock
    SmbFile mockDir;

    /**
     * Happy-path: a filter that accepts any name.
     */
    @ParameterizedTest
    @DisplayName("accepts any non-null/any string")
    @ValueSource(strings = { "file.txt", "data.DAT", "a", "x.y.z", "  spaced  " })
    void acceptsAnyNameReturnsTrue(String input) throws Exception {
        SmbFilenameFilter filter = (dir, name) -> true;

        boolean result = filter.accept(mockDir, input);

        assertTrue(result, "Filter should accept any provided name");
        verifyNoInteractions(mockDir);
    }

    /**
     * Happy-path: a filter that rejects any name.
     */
    @ParameterizedTest
    @DisplayName("rejects every provided name")
    @ValueSource(strings = { "file.txt", "data.DAT", "a", "", "   " })
    void rejectsAnyNameReturnsFalse(String input) throws Exception {
        SmbFilenameFilter filter = (dir, name) -> false;

        boolean result = filter.accept(mockDir, input);

        assertFalse(result, "Filter should reject any provided name");
        verifyNoInteractions(mockDir);
    }

    /**
     * Edge: name-based filter behavior for diverse inputs.
     */
    @ParameterizedTest
    @DisplayName("name-based filter matches .txt case-insensitively")
    @CsvSource({ "notes.txt,true", "REPORT.TXT,true", "image.png,false", "archive.tar.gz,false", "txt,false" })
    void nameBasedFilterTxt(String name, boolean expected) throws Exception {
        SmbFilenameFilter filter = (dir, n) -> n != null && n.toLowerCase().endsWith(".txt");

        boolean result = filter.accept(mockDir, name);

        assertEquals(expected, result, "Filter should evaluate .txt suffix correctly");
        verifyNoInteractions(mockDir);
    }

    /**
     * Invalid/null inputs: ensure filters can handle null name and dir.
     */
    @ParameterizedTest
    @DisplayName("null and empty names are handled explicitly")
    @NullAndEmptySource
    @ValueSource(strings = { " \t\n" })
    void handlesNullAndEmptyNames(String name) throws Exception {
        // Filter accepts only when name is exactly null, otherwise false
        SmbFilenameFilter filter = (dir, n) -> n == null;

        boolean result = filter.accept(mockDir, name);

        if (name == null) {
            assertTrue(result, "Null name should be accepted by this filter");
        } else {
            assertFalse(result, "Non-null names should be rejected by this filter");
        }
        verifyNoInteractions(mockDir);
    }

    /**
     * Edge: passing a null directory object. Interface allows null; implementation decides.
     */
    @Test
    @DisplayName("null directory is handled by implementation")
    void handlesNullDirectory() throws Exception {
        SmbFilenameFilter filter = (dir, name) -> dir == null;

        boolean result = filter.accept(null, "anything");

        assertTrue(result, "Filter should accept when dir is null as defined");
    }

    /**
     * Exception flow: filter throws SmbSystemException and it propagates to caller.
     */
    @Test
    @DisplayName("throws SmbSystemException as declared by contract")
    void throwsSmbExceptionFromFilter() {
        SmbFilenameFilter filter = (dir, name) -> {
            throw new SmbException("boom");
        };

        SmbException ex = assertThrows(SmbException.class, () -> filter.accept(mockDir, "x"));
        assertEquals("boom", ex.getMessage(), "Exception message should be preserved");
        verifyNoInteractions(mockDir);
    }

    /**
     * Interaction with dependency: implementation can use directory's methods to make decisions.
     * Tests a filter that uses directory path information.
     */
    @Test
    @DisplayName("filter can use SmbFile directory for decision logic")
    void filterCanUseSmbFileForDecision() throws Exception {
        // Stub the getPath method to return a specific value
        when(mockDir.getPath()).thenReturn("/share/folder/");

        // Implementation uses dir.getPath() to check if file should be in that path
        SmbFilenameFilter filter = (dir, name) -> {
            if (dir == null)
                return false;
            String path = dir.getPath();
            // Accept files in /share/folder/ that are text files
            return path.equals("/share/folder/") && name != null && name.endsWith(".txt");
        };

        // Act & Assert: test with different file names
        assertTrue(filter.accept(mockDir, "document.txt"), "Should accept .txt files in the correct path");
        assertFalse(filter.accept(mockDir, "image.png"), "Should reject non-.txt files");
        assertFalse(filter.accept(mockDir, null), "Should reject null names");

        // Verify getPath was called three times (once for each accept call)
        verify(mockDir, times(3)).getPath();
        verifyNoMoreInteractions(mockDir);
    }

    /**
     * Defensive behavior: implementation throws NPE on null inputs by design.
     */
    @Test
    @DisplayName("implementation explicitly rejects nulls with NPE")
    void implementationRejectsNulls() {
        SmbFilenameFilter filter = (dir, name) -> {
            if (dir == null || name == null) {
                throw new NullPointerException("dir and name must be non-null");
            }
            return true;
        };

        NullPointerException npe1 = assertThrows(NullPointerException.class, () -> filter.accept(null, "x"));
        assertTrue(npe1.getMessage().contains("non-null"));

        NullPointerException npe2 = assertThrows(NullPointerException.class, () -> filter.accept(mockDir, null));
        assertTrue(npe2.getMessage().contains("non-null"));
        verifyNoInteractions(mockDir);
    }

    /**
     * Sanity: implementing via an anonymous class works the same as a lambda.
     */
    @Test
    @DisplayName("anonymous class implementation behaves correctly")
    void anonymousClassImplementation() throws Exception {
        SmbFilenameFilter filter = new SmbFilenameFilter() {
            @Override
            public boolean accept(SmbFile dir, String name) throws SmbException {
                return name != null && name.length() > 3;
            }
        };

        assertTrue(filter.accept(mockDir, "long"));
        assertFalse(filter.accept(mockDir, "no"));
        verifyNoInteractions(mockDir);
    }
}
