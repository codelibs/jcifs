package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link Handler}.
 *
 * Tests the SMB URL handler implementation including:
 * - Default port configuration
 * - URL connection opening
 * - URL creation and parsing
 */
public class HandlerTest {

    private final Handler handler = new Handler();

    @BeforeAll
    static void setupProtocolHandler() {
        // Register the SMB protocol handler
        String pkgs = System.getProperty("java.protocol.handler.pkgs");
        if (pkgs == null) {
            System.setProperty("java.protocol.handler.pkgs", "jcifs.smb1");
        } else if (!pkgs.contains("jcifs.smb1")) {
            System.setProperty("java.protocol.handler.pkgs", pkgs + "|jcifs.smb1");
        }
    }

    @Test
    @DisplayName("getDefaultPort returns SMB default port 445")
    void testGetDefaultPort() {
        // Act
        int port = handler.getDefaultPort();

        // Assert
        assertEquals(445, port);
        assertEquals(SmbConstants.DEFAULT_PORT, port);
    }

    @Test
    @DisplayName("openConnection creates SmbFile for valid URL")
    void testOpenConnectionWithValidUrl() throws IOException {
        // Arrange - Create URL with handler
        URL url = new URL(null, "smb://host/share", handler);

        // Act
        URLConnection conn = handler.openConnection(url);

        // Assert
        assertNotNull(conn);
        assertTrue(conn instanceof SmbFile);
    }

    @Test
    @DisplayName("openConnection throws NPE for null URL")
    void testOpenConnectionWithNullUrl() {
        // Act & Assert
        assertThrows(NullPointerException.class, () -> handler.openConnection(null));
    }

    @Test
    @DisplayName("URL created with handler parses SMB URL correctly")
    void testUrlCreationWithHandler() throws Exception {
        // Act - Create various SMB URLs using the handler
        URL url1 = new URL(null, "smb://host/share", handler);
        URL url2 = new URL(null, "smb://host:1234/share/file.txt", handler);
        URL url3 = new URL(null, "smb://user:pass@host/share", handler);

        // Assert - Verify URL components
        assertEquals("smb", url1.getProtocol());
        assertEquals("host", url1.getHost());
        assertEquals(445, url1.getPort());
        assertEquals("/share", url1.getPath());

        assertEquals("smb", url2.getProtocol());
        assertEquals("host", url2.getHost());
        assertEquals(1234, url2.getPort());
        assertEquals("/share/file.txt", url2.getPath());

        assertEquals("smb", url3.getProtocol());
        assertEquals("host", url3.getHost());
        assertEquals(445, url3.getPort());
        assertEquals("/share", url3.getPath());
        assertEquals("user:pass", url3.getUserInfo());
    }

    @Test
    @DisplayName("URL handles SMB-specific URL formats")
    void testSmbSpecificUrlFormats() throws Exception {
        // Test empty SMB URL
        URL emptyUrl = new URL(null, "smb://", handler);
        assertEquals("smb", emptyUrl.getProtocol());
        assertEquals("", emptyUrl.getHost());
        assertEquals(445, emptyUrl.getPort());

        // Test SMB URL with only host
        URL hostOnlyUrl = new URL(null, "smb://server", handler);
        assertEquals("smb", hostOnlyUrl.getProtocol());
        assertEquals("server", hostOnlyUrl.getHost());
        assertEquals(445, hostOnlyUrl.getPort());
        assertEquals("", hostOnlyUrl.getPath());

        // Test SMB URL with query parameters
        URL queryUrl = new URL(null, "smb://host/share?param=value", handler);
        assertEquals("smb", queryUrl.getProtocol());
        assertEquals("host", queryUrl.getHost());
        assertEquals("/share", queryUrl.getPath());
        assertEquals("param=value", queryUrl.getQuery());
    }

    @Test
    @DisplayName("URL handles relative paths correctly")
    void testRelativeUrlHandling() throws Exception {
        // Create base URL
        URL baseUrl = new URL(null, "smb://server/share/", handler);

        // Test relative path resolution
        URL relativeUrl = new URL(baseUrl, "folder/file.txt");
        assertEquals("smb", relativeUrl.getProtocol());
        assertEquals("server", relativeUrl.getHost());
        assertEquals("/share/folder/file.txt", relativeUrl.getPath());

        // Test parent directory navigation
        URL parentUrl = new URL(baseUrl, "../other/file.txt");
        assertEquals("smb", parentUrl.getProtocol());
        assertEquals("server", parentUrl.getHost());
        assertEquals("/other/file.txt", parentUrl.getPath());
    }

    @Test
    @DisplayName("Handler correctly identifies itself as SMB handler")
    void testHandlerEquality() throws Exception {
        // Create two URLs with the same handler
        URL url1 = new URL(null, "smb://host1/share1", handler);
        URL url2 = new URL(null, "smb://host2/share2", handler);

        // Both should use the same handler instance
        assertNotNull(url1);
        assertNotNull(url2);

        // Protocol should be consistent
        assertEquals(url1.getProtocol(), url2.getProtocol());
        assertEquals("smb", url1.getProtocol());
    }
}