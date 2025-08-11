package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.io.IOException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@link Handler}.
 * 
 * The test suite aims to exercise all public methods:
 * {@link Handler#getDefaultPort()}, {@link Handler#openConnection(URL)},
 * and {@link Handler#parseURL(URL, String, int, int)}.
 * 
 * Each test follows the Arrange–Act–Assert pattern and documents its
 * intent in a concise English comment.
 */
@ExtendWith(MockitoExtension.class)
public class HandlerTest {

    private final Handler handler = new Handler();

    // GetDefaultPort
    @Test
    @DisplayName("getDefaultPort returns constant")
    void getDefaultPort_returnsConstant() {
        // Arrange & Act
        int port = handler.getDefaultPort();
        // Assert
        assertEquals(SmbConstants.DEFAULT_PORT, port, "getDefaultPort should return the configured default port");
    }

    // OpenConnection
    @Test
    @DisplayName("openConnection returns SmbFile for a valid URL")
    void openConnection_createsSmbFile() throws IOException {
        // Arrange
        URL url = new URL("smb://host/share");
        // Act
        URLConnection conn = handler.openConnection(url);
        // Assert
        assertNotNull(conn, "Connection should not be null");
        assertTrue(conn instanceof SmbFile, "Connection should be an instance of SmbFile");
    }

    @Test
    @DisplayName("openConnection throws NPE when URL is null")
    void openConnection_nullURL_throws() {
        // Act & Assert
        assertThrows(NullPointerException.class, () -> handler.openConnection(null));
    }

    // ParseURL edge cases
    @Nested
    @DisplayName("parseURL edge case handling")
    class ParseUrlEdgeCases {

        static java.util.stream.Stream<Arguments> provideSpecs() {
            return java.util.stream.Stream.of(
                    Arguments.of("smb1://", "smb", "", SmbConstants.DEFAULT_PORT, ""),
                    Arguments.of("//host/share", "smb", "host", SmbConstants.DEFAULT_PORT, "/share"),
                    Arguments.of("smb1://host:1234/share", "smb", "host", 1234, "/share"),
                    Arguments.of("smb1://host/share#frag", "smb", "host", SmbConstants.DEFAULT_PORT, "/share#frag")
            );
        }

        @ParameterizedTest
        @MethodSource("provideSpecs")
        @DisplayName("parseURL sets protocol, host, port and path correctly")
        void parseURL_setsAllParts(String spec, String expectedProtocol, String expectedHost,
                                   int expectedPort, String expectedPath) throws MalformedURLException {
            // Arrange
            URL url = new URL("http://ignored");
            // Act – the parser mutates the URL instance
            handler.parseURL(url, spec, 0, spec.length());
            // Assert
            assertEquals(expectedProtocol, url.getProtocol(), "Protocol mismatch");
            assertEquals(expectedHost, url.getHost(), "Host mismatch");
            assertEquals(expectedPort, url.getPort(), "Port mismatch");
            assertEquals(expectedPath, url.getPath(), "Path mismatch");
        }

        @Test
        @DisplayName("parseURL throws when spec is null")
        void parseURL_nullSpec_throws() throws MalformedURLException {
            URL url = new URL("http://host");
            assertThrows(NullPointerException.class, () -> handler.parseURL(url, null, 0, 0));
        }
    }
}

