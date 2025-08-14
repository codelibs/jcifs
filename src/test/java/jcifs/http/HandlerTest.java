package jcifs.http;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;
import java.util.Map;
import java.util.Properties;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;

/**
 * Tests for the {@link Handler} class.
 * This class tests the functionality of the NTLM URLStreamHandler wrapper.
 */
@ExtendWith(MockitoExtension.class)
class HandlerTest {

    @Mock
    private CIFSContext mockCifsContext;

    private Handler handler;

    private Properties originalSystemProperties;

    @BeforeEach
    void setUp() throws Exception {
        // Backup system properties to restore them after each test
        originalSystemProperties = (Properties) System.getProperties().clone();
        // Reset static state of the Handler class before each test for isolation
        resetHandlerState();
        handler = new Handler(mockCifsContext);
    }

    @AfterEach
    void tearDown() throws Exception {
        // Restore system properties and clean up static state
        System.setProperties(originalSystemProperties);
        resetHandlerState();
    }

    /**
     * Resets the static state of the Handler class using reflection.
     * This is crucial for ensuring that tests are isolated from each other.
     */
    private void resetHandlerState() throws Exception {
        // Reset the static factory field
        Field factoryField = Handler.class.getDeclaredField("factory");
        factoryField.setAccessible(true);
        factoryField.set(null, null);

        // Clear the protocol handlers cache
        Field handlersField = Handler.class.getDeclaredField("PROTOCOL_HANDLERS");
        handlersField.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<String, URLStreamHandler> handlers = (Map<String, URLStreamHandler>) handlersField.get(null);
        handlers.clear();
    }

    /**
     * Pre-populates the protocol handlers cache with mock handlers for testing.
     * This avoids the need for actual protocol handlers to be available.
     */
    private void setupMockProtocolHandlers() throws Exception {
        Field handlersField = Handler.class.getDeclaredField("PROTOCOL_HANDLERS");
        handlersField.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<String, URLStreamHandler> handlers = (Map<String, URLStreamHandler>) handlersField.get(null);

        // Create mock HTTP handler
        URLStreamHandler httpHandler = new URLStreamHandler() {
            @Override
            protected URLConnection openConnection(URL u) throws IOException {
                return mock(HttpURLConnection.class);
            }
        };

        // Create mock HTTPS handler
        URLStreamHandler httpsHandler = new URLStreamHandler() {
            @Override
            protected URLConnection openConnection(URL u) throws IOException {
                return mock(HttpURLConnection.class);
            }
        };

        handlers.put("http", httpHandler);
        handlers.put("https", httpsHandler);
    }

    @Test
    void testGetDefaultPort() {
        // This test verifies that the handler returns the correct default HTTP port.
        assertEquals(Handler.DEFAULT_HTTP_PORT, handler.getDefaultPort(), "Default port should be 80 for HTTP.");
    }

    @Test
    void testOpenConnection_HttpProtocol_ReturnsNtlmHttpURLConnection() throws Exception {
        // This test ensures that for a standard HTTP URL, openConnection wraps the connection
        // in an NtlmHttpURLConnection, using mock handlers to avoid dependency on system handlers.
        setupMockProtocolHandlers();
        URL url = new URL("http://example.com/resource");
        URLConnection connection = handler.openConnection(url);

        assertNotNull(connection, "Connection should not be null.");
        assertTrue(connection instanceof NtlmHttpURLConnection, "Connection should be an instance of NtlmHttpURLConnection.");
    }

    @Test
    void testOpenConnection_HttpsProtocol_ReturnsNtlmHttpURLConnection() throws Exception {
        // This test ensures that for a standard HTTPS URL, openConnection also works and
        // wraps the connection, using mock handlers to avoid dependency on system handlers.
        setupMockProtocolHandlers();
        URL url = new URL("https://example.com/resource");
        URLConnection connection = handler.openConnection(url);

        assertNotNull(connection, "Connection should not be null.");
        assertTrue(connection instanceof NtlmHttpURLConnection, "Connection should be an instance of NtlmHttpURLConnection.");
    }

    @Test
    void testOpenConnection_UnknownProtocol_ThrowsIOException() {
        // This test verifies that attempting to open a connection for an unsupported protocol
        // results in an IOException, as no default handler should be found.
        assertThrows(IOException.class, () -> {
            handler.openConnection(new URL("unknownprotocol://somehost/path"));
        }, "Should throw IOException for an unknown protocol.");
    }

    @Test
    void testSetURLStreamHandlerFactory_SuccessFirstTime() {
        // This test verifies that a URLStreamHandlerFactory can be successfully set.
        URLStreamHandlerFactory mockFactory = mock(URLStreamHandlerFactory.class);
        assertDoesNotThrow(() -> Handler.setURLStreamHandlerFactory(mockFactory),
                "Setting the factory for the first time should not throw an exception.");
    }

    @Test
    void testSetURLStreamHandlerFactory_ThrowsIllegalStateExceptionOnSecondAttempt() {
        // This test ensures that attempting to set the URLStreamHandlerFactory more than once
        // throws an IllegalStateException as per the contract.
        URLStreamHandlerFactory mockFactory1 = mock(URLStreamHandlerFactory.class);
        URLStreamHandlerFactory mockFactory2 = mock(URLStreamHandlerFactory.class);

        Handler.setURLStreamHandlerFactory(mockFactory1); // First call, should succeed.

        assertThrows(IllegalStateException.class, () -> {
            Handler.setURLStreamHandlerFactory(mockFactory2); // Second call, should fail.
        }, "Setting the factory a second time should throw IllegalStateException.");
    }

    @Test
    void testOpenConnection_WithCustomFactory() throws Exception {
        // This test verifies that if a custom URLStreamHandlerFactory is set, it is used
        // to create the stream handler for the connection.
        URLStreamHandlerFactory mockFactory = mock(URLStreamHandlerFactory.class);

        // Create a concrete URLStreamHandler subclass instead of mocking
        URLStreamHandler mockStreamHandler = new URLStreamHandler() {
            @Override
            protected URLConnection openConnection(URL u) throws IOException {
                return mock(HttpURLConnection.class);
            }
        };

        URL url = new URL("http://custom.protocol/path");

        // Configure the mock factory to return our handler for the 'http' protocol.
        when(mockFactory.createURLStreamHandler("http")).thenReturn(mockStreamHandler);

        Handler.setURLStreamHandlerFactory(mockFactory);

        URLConnection connection = handler.openConnection(url);

        assertNotNull(connection, "The resulting connection should not be null.");
        assertTrue(connection instanceof NtlmHttpURLConnection, "Connection must be wrapped in NtlmHttpURLConnection.");

        // Verify that our custom factory was indeed used.
        verify(mockFactory).createURLStreamHandler("http");
    }

    @Test
    void testOpenConnection_WithSystemPropertyHandler_SkipsJcifsPackage() throws Exception {
        // This test verifies that the handler resolution mechanism correctly skips the 'jcifs'
        // package when it is listed in the 'java.protocol.handler.pkgs' system property.
        // We use mock handlers since actual system handlers might not be available in test environment.
        System.setProperty("java.protocol.handler.pkgs", "jcifs");
        setupMockProtocolHandlers();
        URL url = new URL("http://example.com/resource");

        URLConnection connection = handler.openConnection(url);

        assertNotNull(connection, "Connection should not be null even when jcifs is in handler path.");
        assertTrue(connection instanceof NtlmHttpURLConnection, "Should use cached handler and wrap it.");
    }

    @Test
    void testOpenConnection_NullSystemProperty_UsesDefaultHandlers() throws Exception {
        // This test verifies that when the system property is null, the handler
        // falls back to using default handlers without throwing NullPointerException.
        System.clearProperty("java.protocol.handler.pkgs");
        setupMockProtocolHandlers();
        URL url = new URL("http://example.com/resource");

        URLConnection connection = handler.openConnection(url);

        assertNotNull(connection, "Connection should not be null when system property is null.");
        assertTrue(connection instanceof NtlmHttpURLConnection, "Should use cached handler and wrap it.");
    }

    @Test
    void testOpenConnection_EmptySystemProperty_UsesDefaultHandlers() throws Exception {
        // This test verifies that when the system property is empty, the handler
        // falls back to using default handlers.
        System.setProperty("java.protocol.handler.pkgs", "");
        setupMockProtocolHandlers();
        URL url = new URL("http://example.com/resource");

        URLConnection connection = handler.openConnection(url);

        assertNotNull(connection, "Connection should not be null when system property is empty.");
        assertTrue(connection instanceof NtlmHttpURLConnection, "Should use cached handler and wrap it.");
    }

    @Test
    void testOpenConnection_CachedHandler_ReusesExistingHandler() throws Exception {
        // This test verifies that once a handler is cached, subsequent calls reuse it.
        setupMockProtocolHandlers();
        URL url1 = new URL("http://example.com/resource1");
        URL url2 = new URL("http://example.com/resource2");

        URLConnection connection1 = handler.openConnection(url1);
        URLConnection connection2 = handler.openConnection(url2);

        assertNotNull(connection1, "First connection should not be null.");
        assertNotNull(connection2, "Second connection should not be null.");
        assertTrue(connection1 instanceof NtlmHttpURLConnection, "First connection should be wrapped.");
        assertTrue(connection2 instanceof NtlmHttpURLConnection, "Second connection should be wrapped.");
    }
}
