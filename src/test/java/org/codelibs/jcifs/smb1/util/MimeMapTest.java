package org.codelibs.jcifs.smb1.util;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class MimeMapTest {

    private MimeMap mimeMap;

    @BeforeEach
    void setUp() throws IOException {
        mimeMap = new MimeMap();
    }

    @Nested
    @DisplayName("getMimeType with extension only")
    class GetMimeTypeWithExtension {

        @Test
        @DisplayName("Should return correct mime type for known extensions")
        void testKnownExtensions() throws IOException {
            assertEquals("application/pdf", mimeMap.getMimeType("pdf"));
            assertEquals("application/msword", mimeMap.getMimeType("doc"));
            assertEquals("application/vnd.ms-excel", mimeMap.getMimeType("xls"));
            assertEquals("text/html", mimeMap.getMimeType("html"));
            assertEquals("text/html", mimeMap.getMimeType("htm"));
            assertEquals("image/jpeg", mimeMap.getMimeType("jpg"));
            assertEquals("image/jpeg", mimeMap.getMimeType("jpeg"));
            assertEquals("image/gif", mimeMap.getMimeType("gif"));
            assertEquals("image/png", mimeMap.getMimeType("png"));
        }

        @Test
        @DisplayName("Should return default mime type for unknown extensions")
        void testUnknownExtension() throws IOException {
            assertEquals("application/octet-stream", mimeMap.getMimeType("unknownext"));
            assertEquals("application/octet-stream", mimeMap.getMimeType("notfound"));
            assertEquals("application/octet-stream", mimeMap.getMimeType("doesnotexist"));
        }

        @Test
        @DisplayName("Should handle case insensitive extensions")
        void testCaseInsensitiveExtensions() throws IOException {
            assertEquals("application/pdf", mimeMap.getMimeType("PDF"));
            assertEquals("application/pdf", mimeMap.getMimeType("Pdf"));
            assertEquals("application/pdf", mimeMap.getMimeType("pDf"));
            assertEquals("text/html", mimeMap.getMimeType("HTML"));
            assertEquals("text/html", mimeMap.getMimeType("HtMl"));
        }

        @ParameterizedTest
        @DisplayName("Should return correct mime type for multiple extensions")
        @CsvSource({ "txt, text/plain", "css, text/css", "js, application/x-javascript", "zip, application/zip", "tar, application/x-tar",
                "gz, application/x-gzip", "tiff, image/tiff", "tif, image/tiff" })
        void testVariousExtensions(String extension, String expectedMimeType) throws IOException {
            assertEquals(expectedMimeType, mimeMap.getMimeType(extension));
        }

        @Test
        @DisplayName("Should handle extensions with special characters")
        void testSpecialCharacterExtensions() throws IOException {
            // Test extensions that are definitely not in the map
            assertEquals("application/octet-stream", mimeMap.getMimeType("file.ext"));
            assertEquals("application/octet-stream", mimeMap.getMimeType("@#$%"));
            assertEquals("application/octet-stream", mimeMap.getMimeType("test123abc"));
        }
    }

    @Nested
    @DisplayName("getMimeType with custom default")
    class GetMimeTypeWithDefault {

        @Test
        @DisplayName("Should return custom default for unknown extensions")
        void testCustomDefaultForUnknown() throws IOException {
            String customDefault = "application/custom";
            assertEquals(customDefault, mimeMap.getMimeType("unknownext", customDefault));
            assertEquals(customDefault, mimeMap.getMimeType("notfound", customDefault));
            assertEquals(customDefault, mimeMap.getMimeType("doesnotexist", customDefault));
        }

        @Test
        @DisplayName("Should return actual mime type for known extensions")
        void testKnownExtensionsWithDefault() throws IOException {
            String customDefault = "application/custom";
            assertEquals("application/pdf", mimeMap.getMimeType("pdf", customDefault));
            assertEquals("text/html", mimeMap.getMimeType("html", customDefault));
            assertEquals("image/jpeg", mimeMap.getMimeType("jpg", customDefault));
        }

        @ParameterizedTest
        @DisplayName("Should handle various default values")
        @ValueSource(strings = { "text/unknown", "application/x-unknown", "custom/type", "" })
        void testVariousDefaultValues(String defaultValue) throws IOException {
            assertEquals(defaultValue, mimeMap.getMimeType("notinmap", defaultValue));
        }
    }

    @Nested
    @DisplayName("Edge cases and special scenarios")
    class EdgeCases {

        @Test
        @DisplayName("Should handle multiple extensions for same mime type")
        void testMultipleExtensionsForSameMimeType() throws IOException {
            // Both jpg and jpeg should map to image/jpeg
            String jpgMime = mimeMap.getMimeType("jpg");
            String jpegMime = mimeMap.getMimeType("jpeg");
            assertEquals(jpgMime, jpegMime);
            assertEquals("image/jpeg", jpgMime);

            // Both htm and html should map to text/html
            String htmMime = mimeMap.getMimeType("htm");
            String htmlMime = mimeMap.getMimeType("html");
            assertEquals(htmMime, htmlMime);
            assertEquals("text/html", htmMime);
        }

        @Test
        @DisplayName("Should handle binary file extensions")
        void testBinaryFileExtensions() throws IOException {
            assertEquals("application/octet-stream", mimeMap.getMimeType("bin"));
            assertEquals("application/octet-stream", mimeMap.getMimeType("exe"));
            assertEquals("application/octet-stream", mimeMap.getMimeType("ani"));
        }

        @Test
        @DisplayName("Should handle Microsoft Office extensions")
        void testMicrosoftOfficeExtensions() throws IOException {
            assertEquals("application/msword", mimeMap.getMimeType("doc"));
            assertEquals("application/vnd.ms-excel", mimeMap.getMimeType("xls"));
            assertEquals("application/mspowerpoint", mimeMap.getMimeType("ppt"));
        }

        @Test
        @DisplayName("Should handle audio and video extensions")
        void testMultimediaExtensions() throws IOException {
            // Common audio formats
            assertEquals("audio/x-wav", mimeMap.getMimeType("wav"));
            // mp3 has multiple mappings, first one wins
            assertEquals("audio/x-mpegurl", mimeMap.getMimeType("mp3"));

            // Common video formats
            assertEquals("video/x-msvideo", mimeMap.getMimeType("avi"));
            assertEquals("video/mpeg", mimeMap.getMimeType("mpeg"));
            assertEquals("video/quicktime", mimeMap.getMimeType("mov"));
        }

        @Test
        @DisplayName("Should handle empty extensions safely")
        void testEmptyExtensions() throws IOException {
            // Empty extension seems to match first entry in mime.map
            String result = mimeMap.getMimeType("");
            assertNotNull(result);
            // With custom default, empty still returns the first match
            String customResult = mimeMap.getMimeType("", "custom/default");
            assertNotNull(customResult);
        }
    }

    @Nested
    @DisplayName("Constructor and initialization")
    class ConstructorTests {

        @Test
        @DisplayName("Should create MimeMap instance successfully")
        void testConstructor() {
            assertDoesNotThrow(() -> new MimeMap());
        }

        @Test
        @DisplayName("Should load mime.map resource properly")
        void testResourceLoading() throws IOException {
            MimeMap map = new MimeMap();
            assertNotNull(map);
            // Verify it works by testing a known mapping
            assertEquals("application/pdf", map.getMimeType("pdf"));
        }
    }

    @Nested
    @DisplayName("Performance and concurrency")
    class PerformanceTests {

        @Test
        @DisplayName("Should handle multiple lookups efficiently")
        void testMultipleLookups() throws IOException {
            // Test that multiple lookups work correctly
            for (int i = 0; i < 100; i++) {
                assertEquals("application/pdf", mimeMap.getMimeType("pdf"));
                assertEquals("text/html", mimeMap.getMimeType("html"));
                assertEquals("image/jpeg", mimeMap.getMimeType("jpg"));
            }
        }

        @Test
        @DisplayName("Should handle rapid succession of different extensions")
        void testRapidDifferentExtensions() throws IOException {
            String[] extensions = { "pdf", "doc", "xls", "html", "jpg", "gif", "png", "txt", "xml", "css" };
            for (String ext : extensions) {
                assertNotNull(mimeMap.getMimeType(ext));
            }
        }
    }
}