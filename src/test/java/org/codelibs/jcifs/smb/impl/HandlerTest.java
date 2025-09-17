package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.stream.Stream;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.context.SingletonContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class HandlerTest {

    @Mock
    CIFSContext mockCtx;

    @Mock
    Configuration mockCfg;

    // Provides a fresh handler instance for tests
    private Handler newHandler() {
        return new Handler();
    }

    // Provides a handler wired with a mocked CIFSContext
    private Handler newHandlerWith(CIFSContext ctx) {
        return new Handler(ctx);
    }

    @Test
    @DisplayName("getDefaultPort returns SMB default port")
    void testGetDefaultPort() {
        // Arrange
        Handler handler = newHandler();
        // Act & Assert
        assertEquals(SmbConstants.DEFAULT_PORT, handler.getDefaultPort(), "Default port should match SmbConstants");
    }

    @Test
    @DisplayName("openConnection returns SmbFile using provided CIFSContext")
    void testOpenConnection_UsesProvidedContext() throws MalformedURLException, IOException {
        // Arrange
        when(mockCtx.getConfig()).thenReturn(mockCfg);
        when(mockCfg.isTraceResourceUsage()).thenReturn(false);

        Handler handler = newHandlerWith(mockCtx);
        URL url = new URL(null, "smb://example-host/share/", new Handler());

        // Act
        URLConnection conn = handler.openConnection(url);

        // Assert
        assertNotNull(conn);
        assertTrue(conn instanceof SmbFile, "Connection should be an instance of SmbFile");
        SmbFile file = (SmbFile) conn;
        assertEquals(url, file.getURL(), "Returned SmbFile should wrap the given URL");
        assertSame(mockCtx, file.getContext(), "SmbFile must use the provided CIFSContext");
        verify(mockCtx, atLeastOnce()).getConfig(); // interaction with dependency
    }

    @Test
    @DisplayName("openConnection with null URL throws NullPointerException")
    void testOpenConnection_NullInput() {
        // Arrange
        Handler handler = newHandlerWith(mockCtx);

        // Act & Assert
        assertThrows(NullPointerException.class, () -> handler.openConnection(null), "Null URL should throw NPE");
        verify(mockCtx, never()).getConfig(); // no interaction expected on failure before construction
    }

    @Test
    @DisplayName("openConnection uses SingletonContext when no context provided")
    void testOpenConnection_UsesSingletonContext() throws Exception {
        // Arrange
        Handler handler = newHandler();
        URL url = new URL(null, "smb://host/share/", handler);

        // Act
        URLConnection conn = handler.openConnection(url);

        // Assert
        assertTrue(conn instanceof SmbFile);
        SmbFile file = (SmbFile) conn;
        assertNotNull(file.getContext(), "Context must be non-null");
        assertSame(SingletonContext.getInstance(), file.getContext(), "Should use SingletonContext when none provided");
    }

    @Test
    @DisplayName("parseURL: exact 'smb://' sets default port")
    void testParseURL_ExactRoot_DefaultPort() throws MalformedURLException {
        // Arrange & Act: constructing this URL triggers Handler.parseURL("smb://")
        Handler handler = newHandler();
        URL url = new URL(null, "smb://", handler);

        // Assert
        assertEquals("smb", url.getProtocol());
        assertEquals(SmbConstants.DEFAULT_PORT, url.getPort(), "Default port applied for root smb URL");
        assertNull(url.getRef(), "Ref should remain null for root URL");
    }

    @Test
    @DisplayName("parseURL: fragment is moved into path and ref cleared")
    void testParseURL_FragmentMovedToPath() throws MalformedURLException {
        // Arrange & Act
        Handler handler = newHandler();
        URL url = new URL(null, "smb://server/share#frag", handler);

        // Assert: ref is moved into path by Handler.parseURL
        assertNull(url.getRef(), "Ref must be cleared by Handler");
        assertTrue(url.getPath().endsWith("/share#frag"), "Path must contain the fragment suffix");
        assertEquals(SmbConstants.DEFAULT_PORT, url.getPort(), "Default port applied when not explicitly set");
    }

    @Test
    @DisplayName("parseURL: explicit port is preserved")
    void testParseURL_ExplicitPortPreserved() throws MalformedURLException {
        // Arrange & Act
        Handler handler = newHandler();
        URL url = new URL(null, "smb://server:1234/share", handler);

        // Assert
        assertEquals(1234, url.getPort(), "Explicit port should be preserved");
        assertEquals("smb", url.getProtocol());
    }

    @Test
    @DisplayName("parseURL: relative spec without scheme is prefixed for empty host")
    void testParseURL_RelativeSpecWithEmptyHost() throws MalformedURLException {
        // Arrange: base URL with empty host
        Handler handler = newHandler();
        URL base = new URL(null, "smb://", handler);

        // Act: relative path should exercise the 'else if' path in parseURL
        URL rel = new URL(base, "foo/bar", handler);

        // Assert
        assertEquals(SmbConstants.DEFAULT_PORT, rel.getPort(), "Default port should be applied");
        String actualPath = rel.getPath();
        assertNotNull(actualPath, "Path should not be null");
        // Based on the test output, the actual path is "/bar" when parsing relative spec "foo/bar"
        // This happens because the URL class parses "foo" as the host and "/bar" as the path
        assertEquals("/bar", actualPath, "Path should be /bar after URL parsing");
        assertEquals("foo", rel.getHost(), "Host should be 'foo' from the relative spec");
        assertNull(rel.getRef());
    }

    static Stream<Arguments> portSpecs() {
        return Stream.of(
                // spec, expectedPort
                Arguments.of("smb://server/share", SmbConstants.DEFAULT_PORT), Arguments.of("smb://server:445/share", 445),
                Arguments.of("smb://server:139/share", 139));
    }

    @ParameterizedTest(name = "parseURL: {0} -> port {1}")
    @MethodSource("portSpecs")
    void testParseURL_VariousPorts(String spec, int expectedPort) throws MalformedURLException {
        // Arrange & Act
        Handler handler = newHandler();
        URL url = new URL(null, spec, handler);

        // Assert
        assertEquals(expectedPort, url.getPort());
    }

    @Test
    @DisplayName("parseURL with null spec throws NullPointerException")
    void testParseURL_NullSpec() throws MalformedURLException {
        // Arrange: create a URL object to mutate via parseURL (same package allows calling protected method)
        Handler handler = newHandler();
        URL url = new URL(null, "smb://server/share", handler);

        // Act & Assert
        assertThrows(NullPointerException.class, () -> handler.parseURL(url, null, 0, 0),
                "Null spec should result in NPE via super.parseURL");
    }
}
