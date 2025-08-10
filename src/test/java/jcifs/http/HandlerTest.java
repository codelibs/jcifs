package jcifs.http;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
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

    @Test
    void testGetDefaultPort() {
        // This test verifies that the handler returns the correct default HTTP port.
        assertEquals(Handler.DEFAULT_HTTP_PORT, handler.getDefaultPort(), "Default port should be 80 for HTTP.");
    }

    @Test
    void testOpenConnection_HttpProtocol_ReturnsNtlmHttpURLConnection() throws IOException {
        // This test ensures that for a standard HTTP URL, openConnection wraps the connection
        // in an NtlmHttpURLConnection, relying on the default Java protocol handlers.
        URL url = new URL("http://example.com/resource");
        URLConnection connection = handler.openConnection(url);

        assertNotNull(connection, "Connection should not be null.");
        assertTrue(connection instanceof NtlmHttpURLConnection, "Connection should be an instance of NtlmHttpURLConnection.");
    }

    @Test
    void testOpenConnection_HttpsProtocol_ReturnsNtlmHttpURLConnection() throws IOException {
        // This test ensures that for a standard HTTPS URL, openConnection also works and
        // wraps the connection, relying on the default Java protocol handlers for HTTPS.
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
        URLStreamHandler mockStreamHandler = mock(URLStreamHandler.class);
        HttpURLConnection mockHttpConnection = mock(HttpURLConnection.class);
        URL url = new URL("http://custom.protocol/path");

        // Configure the mock factory to return our mock handler for the 'http' protocol.
        when(mockFactory.createURLStreamHandler("http")).thenReturn(mockStreamHandler);
        // The Handler creates a new URL internally, so we mock the openConnection call
        // on our custom handler to return a specific mock connection.
        when(mockStreamHandler.openConnection(any(URL.class))).thenReturn(mockHttpConnection);

        Handler.setURLStreamHandlerFactory(mockFactory);

        URLConnection connection = handler.openConnection(url);

        assertNotNull(connection, "The resulting connection should not be null.");
        assertTrue(connection instanceof NtlmHttpURLConnection, "Connection must be wrapped in NtlmHttpURLConnection.");

        // Verify that our custom factory was indeed used.
        verify(mockFactory).createURLStreamHandler("http");

        // Use reflection to access the wrapped connection inside NtlmHttpURLConnection
        // and assert that it is the one our mock handler provided.
        Field connField = NtlmHttpURLConnection.class.getDeclaredField("conn");
        connField.setAccessible(true);
        HttpURLConnection wrappedConn = (HttpURLConnection) connField.get(connection);
        assertEquals(mockHttpConnection, wrappedConn, "The wrapped connection should be our mock.");
    }

    @Test
    void testOpenConnection_WithSystemPropertyHandler_SkipsJcifsPackage() throws IOException {
        // This test verifies that the handler resolution mechanism correctly skips the 'jcifs'
        // package when it is listed in the 'java.protocol.handler.pkgs' system property,
        // falling back to the next available handler (the default sun handler).
        System.setProperty("java.protocol.handler.pkgs", "jcifs|sun.net.www.protocol");
        URL url = new URL("http://example.com/resource");
        
        URLConnection connection = handler.openConnection(url);
        
        assertNotNull(connection, "Connection should not be null even when jcifs is in handler path.");
        assertTrue(connection instanceof NtlmHttpURLConnection, "Should fall back to default handler and wrap it.");
    }
}
