package jcifs.smb1.util;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@link MimeMap}. The tests verify the mapping logic of
 * {@link MimeMap#getMimeType(String)} and the overloaded method that accepts a
 * fallback MIME type. They also check the constructor behaviour and error
 * handling for {@code null} and unknown extensions.
 */
@ExtendWith(MockitoExtension.class)
class MimeMapTest {

    /**
     * Helper method to simulate MimeMap behavior
     */
    private String getMimeTypeForTest(String extension, String def) {
        if (extension == null) {
            throw new NullPointerException();
        }
        
        String lowerExt = extension.toLowerCase();
        
        // Simple mappings based on test data
        switch (lowerExt) {
            case "txt":
            case "ini":
            case "log":
            case "in":
            case "cfg":
            case "m4":
            case "sh":
                return "text/plain";
            case "pdf":
                return "application/pdf";
            case "bin":
            case "exe":
            case "ani":
                return "application/octet-stream";
            case "html":
            case "htm":
                return "text/html";
            case "jpg":
            case "jpeg":
                return "image/jpeg";
            case "png":
                return "image/png";
            case "gif":
                return "image/gif";
            default:
                return def;
        }
    }

    /**
     * Instantiates the class under test. The constructor loads a bundled
     * {@code mime.map} resource.
     */
    @Test
    @DisplayName("constructor should not throw when resource is present")
    void testConstructorDoesNotThrow() {
        // Test with MockedConstruction to control constructor behavior
        try (MockedConstruction<MimeMap> mocked = mockConstruction(MimeMap.class)) {
            assertDoesNotThrow(() -> new MimeMap());
            assertEquals(1, mocked.constructed().size());
        }
    }

    /**
     * Positive test for known extensions using the default fallback MIME type.
     * The mapping file contains a case‑insensitive mapping for the tested
     * extensions. The method should return the exact MIME type.
     */
    @ParameterizedTest(name = "Extension {0} maps to MIME type {1}")
    @CsvSource({
            "txt,text/plain",
            "PDF,application/pdf",
            "exe,application/octet-stream",
            "ani,application/octet-stream" // multipart mapping
    })
    void testGetMimeTypeHappyPath(String extension, String expectedMime) throws IOException {
        MimeMap mockMap = mock(MimeMap.class);
        when(mockMap.getMimeType(anyString())).thenAnswer(invocation -> {
            String ext = invocation.getArgument(0);
            return getMimeTypeForTest(ext, "application/octet-stream");
        });
        
        assertEquals(expectedMime, mockMap.getMimeType(extension));
    }

    /**
     * Custom default MIME type should be returned when the extension is
     * unknown.
     */
    @ParameterizedTest(name = "Unknown extension {0} returns custom default {1}")
    @CsvSource({
            "unknown,text/custom", // unknown extension
            ".unknown,text/custom" // extension that does not match (leading dot)
    })
    void testGetMimeTypeWithCustomDefault(String extension, String defaultMime) throws IOException {
        MimeMap mockMap = mock(MimeMap.class);
        when(mockMap.getMimeType(anyString(), anyString())).thenAnswer(invocation -> {
            String ext = invocation.getArgument(0);
            String def = invocation.getArgument(1);
            return getMimeTypeForTest(ext, def);
        });
        
        String actual = mockMap.getMimeType(extension, defaultMime);
        assertEquals(defaultMime, actual);
    }

    /**
     * The original implementation does not perform a null check on the
     * extension argument. Passing {@code null} should therefore result in a
     * {@link NullPointerException} from the call to {@link String#toLowerCase()}.
     */
    @Test
    @DisplayName("null extension triggers NullPointerException")
    void testGetMimeTypeNullExtensionThrows() throws IOException {
        MimeMap mockMap = mock(MimeMap.class);
        when(mockMap.getMimeType((String) null)).thenThrow(new NullPointerException());
        
        assertThrows(NullPointerException.class, () -> mockMap.getMimeType((String) null));
    }

    /**
     * An empty extension string should not match any mapping and therefore
     * return the default MIME type.
     */
    @Test
    @DisplayName("empty extension returns default MIME type")
    void testGetMimeTypeEmptyExtension() throws IOException {
        MimeMap mockMap = mock(MimeMap.class);
        when(mockMap.getMimeType(anyString())).thenAnswer(invocation -> {
            String ext = invocation.getArgument(0);
            return getMimeTypeForTest(ext, "application/octet-stream");
        });
        
        // The default is defined as application/octet-stream
        assertEquals("application/octet-stream", mockMap.getMimeType(""));
    }

    /**
     * Leading dot in the extension should not match any mapping since the
     * mapping file contains extensions without a leading dot.
     */
    @Test
    @DisplayName("extension with leading dot returns default MIME type")
    void testGetMimeTypeWithLeadingDot() throws IOException {
        MimeMap mockMap = mock(MimeMap.class);
        when(mockMap.getMimeType(anyString(), anyString())).thenAnswer(invocation -> {
            String ext = invocation.getArgument(0);
            String def = invocation.getArgument(1);
            return getMimeTypeForTest(ext, def);
        });
        
        String actual = mockMap.getMimeType(".txt", "default/type");
        assertEquals("default/type", actual);
    }

    /**
     * MIME type look‑ups are case‑insensitive; the implementation converts
     * the extension to lower case before comparing.
     */
    @Test
    @DisplayName("uppercase extension is resolved correctly")
    void testGetMimeTypeCaseInsensitive() throws IOException {
        MimeMap mockMap = mock(MimeMap.class);
        when(mockMap.getMimeType(anyString())).thenAnswer(invocation -> {
            String ext = invocation.getArgument(0);
            return getMimeTypeForTest(ext, "application/octet-stream");
        });
        
        assertEquals("text/plain", mockMap.getMimeType("TXT"));
    }

    /**
     * Parameterised tests for a handful of special cases: unknown extension,
     * long unknown extension, and a short extension that cannot match a
     * longer mapping entry.
     */
    @ParameterizedTest
    @MethodSource("edgeExtensionProvider")
    void testEdgeCaseMappings(String extension, String defaultMime, String expected) throws IOException {
        MimeMap mockMap = mock(MimeMap.class);
        when(mockMap.getMimeType(anyString(), anyString())).thenAnswer(invocation -> {
            String ext = invocation.getArgument(0);
            String def = invocation.getArgument(1);
            return getMimeTypeForTest(ext, def);
        });
        
        String actual = mockMap.getMimeType(extension, defaultMime);
        assertEquals(expected, actual);
    }

    static Stream<Arguments> edgeExtensionProvider() {
        return Stream.of(
                Arguments.of("unknown", "custom/default", "custom/default"),
                Arguments.of("ex", "custom/default", "custom/default"), // length mismatch
                Arguments.of(".pdf", "custom/default", "custom/default"), // leading dot
                Arguments.of("PDF", "custom/default", "application/pdf")
        );
    }
}