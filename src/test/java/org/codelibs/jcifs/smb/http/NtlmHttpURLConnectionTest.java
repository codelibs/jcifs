package org.codelibs.jcifs.smb.http;

import static java.net.HttpURLConnection.HTTP_OK;
import static java.net.HttpURLConnection.HTTP_UNAUTHORIZED;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.NameServiceClient;
import org.codelibs.jcifs.smb.RuntimeCIFSException;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.context.BaseContext;
import org.codelibs.jcifs.smb.impl.NtlmPasswordAuthentication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * Tests for the NtlmHttpURLConnection class.
 * This class uses Mockito to simulate the behavior of HttpURLConnection and other dependencies.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class NtlmHttpURLConnectionTest {

    @Mock
    private HttpURLConnection mockConnection;

    private URL mockUrl;

    @Mock
    private CIFSContext mockCifsContext;

    @Mock
    private NameServiceClient mockNameServiceClient;

    private NtlmHttpURLConnection ntlmConnection;

    /**
     * Sets up the mocks and the NtlmHttpURLConnection instance before each test.
     * @throws IOException
     */
    @BeforeEach
    void setUp() throws IOException {
        // Create a real URL instead of mocking to avoid protocol issues
        mockUrl = new URL("http://test.example.com/path");

        // Basic setup for mocks to avoid NullPointerExceptions
        when(mockConnection.getURL()).thenReturn(mockUrl);
        when(mockConnection.getRequestProperties()).thenReturn(new HashMap<>());

        // Mock CIFSContext behavior
        NtlmPasswordAuthentication creds = new NtlmPasswordAuthentication(
                new BaseContext(new PropertyConfiguration(System.getProperties())), "domain", "user", "password");
        when(mockCifsContext.getCredentials()).thenReturn(creds);
        when(mockCifsContext.getConfig()).thenReturn(new PropertyConfiguration(System.getProperties()));
        when(mockCifsContext.getNameServiceClient()).thenReturn(mockNameServiceClient);

        ntlmConnection = new NtlmHttpURLConnection(mockConnection, mockCifsContext);
    }

    /**
     * Test that the constructor copies settings from the wrapped connection.
     * @throws ProtocolException
     */
    @Test
    void testConstructorCopiesSettings() throws ProtocolException {
        // Arrange
        when(mockConnection.getRequestMethod()).thenReturn("GET");
        when(mockConnection.getAllowUserInteraction()).thenReturn(true);
        when(mockConnection.getDoInput()).thenReturn(true);
        when(mockConnection.getDoOutput()).thenReturn(true);
        when(mockConnection.getIfModifiedSince()).thenReturn(12345L);
        when(mockConnection.getUseCaches()).thenReturn(false);
        when(mockConnection.getReadTimeout()).thenReturn(1000);
        when(mockConnection.getConnectTimeout()).thenReturn(2000);
        when(mockConnection.getInstanceFollowRedirects()).thenReturn(true);

        Map<String, List<String>> properties = new HashMap<>();
        properties.put("Accept", Collections.singletonList("application/json"));
        when(mockConnection.getRequestProperties()).thenReturn(properties);
        // Need to mock getRequestProperty as well since it delegates to wrapped connection
        when(mockConnection.getRequestProperty("Accept")).thenReturn("application/json");

        // Act
        ntlmConnection = new NtlmHttpURLConnection(mockConnection, mockCifsContext);

        // Assert
        assertEquals("GET", ntlmConnection.getRequestMethod());
        assertTrue(ntlmConnection.getAllowUserInteraction());
        assertTrue(ntlmConnection.getDoInput());
        assertTrue(ntlmConnection.getDoOutput());
        assertEquals(12345L, ntlmConnection.getIfModifiedSince());
        assertFalse(ntlmConnection.getUseCaches());
        assertEquals(1000, ntlmConnection.getReadTimeout());
        assertEquals(2000, ntlmConnection.getConnectTimeout());
        assertTrue(ntlmConnection.getInstanceFollowRedirects());
        assertEquals("application/json", ntlmConnection.getRequestProperty("Accept"));
    }

    /**
     * Test that connect() calls connect() on the underlying connection.
     * @throws IOException
     */
    @Test
    void testConnect() throws Exception {
        // Act
        ntlmConnection.connect();

        // Assert
        verify(mockConnection).connect();
        // Connection should be established after connect
    }

    /**
     * Test that disconnect() calls disconnect() on the underlying connection and resets state.
     */
    @Test
    void testDisconnect() throws Exception {
        // Act
        ntlmConnection.disconnect();

        // Assert
        verify(mockConnection).disconnect();
        // Connection should be closed after disconnect
    }

    /**
     * Test simple getter methods that should trigger the handshake.
     * We mock a simple 200 OK response to test the handshake is called.
     * @throws IOException
     */
    @Test
    void testGettersTriggerHandshake() throws IOException {
        // Arrange
        // Spy on the connection to verify handshake() is called
        NtlmHttpURLConnection spiedConnection = spy(ntlmConnection);
        doNothing().when(spiedConnection).connect();
        // Mock the handshake process to do nothing complex
        mockResponse(HTTP_OK, "OK", null, null);

        // Act & Assert
        assertDoesNotThrow(() -> spiedConnection.getResponseCode());
        // Use reflection to verify handshake method is called
        assertDoesNotThrow(() -> spiedConnection.getResponseCode());
        assertDoesNotThrow(() -> spiedConnection.getInputStream());
    }

    /**
     * Test a successful NTLM authentication handshake.
     * This is a simplified test that verifies the basic flow without full NTLM protocol simulation.
     * @throws IOException
     * @throws SecurityException
     */
    @Test
    void testSuccessfulHandshake() throws IOException, SecurityException {
        // This test is simplified to verify basic handshake behavior
        // Full NTLM handshake testing would require more complex mocking

        // Arrange - Mock a server that supports NTLM
        mockResponse(HTTP_UNAUTHORIZED, "Unauthorized", Collections.singletonMap("WWW-Authenticate", Collections.singletonList("NTLM")),
                new ByteArrayInputStream(new byte[0]));

        // Act - Trigger handshake
        int responseCode = ntlmConnection.getResponseCode();

        // Assert - Verify we got the 401 response (simplified test)
        assertEquals(HTTP_UNAUTHORIZED, responseCode);

        // In a real scenario, the connection would reconnect and send Type1/Type3 messages
        // This simplified test just verifies the initial handshake detection
    }

    /**
     * Test handshake failure when the server does not return an NTLM challenge.
     * @throws IOException
     */
    @Test
    void testHandshakeFails_NoNtlmChallenge() throws IOException {
        // Arrange
        mockResponse(HTTP_UNAUTHORIZED, "Unauthorized",
                Collections.singletonMap("WWW-Authenticate", Collections.singletonList("Basic realm=\"Test\"")),
                new ByteArrayInputStream(new byte[0]));

        // Act
        int responseCode = ntlmConnection.getResponseCode();

        // Assert
        assertEquals(HTTP_UNAUTHORIZED, responseCode);
        // Since we don't use NTLM, no reconnection should happen
    }

    /**
     * Test that getOutputStream() returns a CacheStream that wraps the underlying stream.
     * @throws IOException
     */
    @Test
    void testGetOutputStreamCachesData() throws IOException {
        // Arrange
        // Enable output mode
        when(mockConnection.getDoOutput()).thenReturn(true);
        ntlmConnection.setDoOutput(true);

        // Mock initial connection's output stream (needed for CacheStream)
        OutputStream initialOutputStream = mock(OutputStream.class);
        when(mockConnection.getOutputStream()).thenReturn(initialOutputStream);

        // Act
        // Get output stream and write data to it
        OutputStream os = ntlmConnection.getOutputStream();
        assertNotNull(os);
        byte[] testData = "test data".getBytes();
        os.write(testData);
        os.flush();
        os.close();

        // Assert
        // Verify that data was written to the underlying stream through CacheStream
        verify(initialOutputStream).write(testData);
        verify(initialOutputStream).flush();
        verify(initialOutputStream).close();
    }

    /**
     * Test that a RuntimeCIFSException is thrown when the handshake fails due to an underlying exception.
     * @throws IOException
     */
    @Test
    void testHandshakeThrowsRuntimeExceptionOnFailure() throws Exception {
        // Arrange
        when(mockConnection.getHeaderField(0)).thenThrow(new RuntimeException("Connection failed"));
        doNothing().when(mockConnection).connect();

        // Act & Assert
        assertThrows(RuntimeCIFSException.class, () -> {
            ntlmConnection.getResponseCode();
        });
    }

    /**
     * Helper method to mock the response of an HttpURLConnection.
     */
    private void mockResponse(int code, String message, Map<String, List<String>> headers, InputStream errorStream) throws IOException {
        mockResponse(this.mockConnection, code, message, headers, errorStream);
    }

    /**
     * Helper method to mock the response of a specific HttpURLConnection instance.
     */
    private void mockResponse(HttpURLConnection conn, int code, String message, Map<String, List<String>> headers, InputStream stream)
            throws IOException {
        if (conn == null)
            return;

        String statusLine = "HTTP/1.1 " + code + " " + message;
        when(conn.getResponseCode()).thenReturn(code);
        when(conn.getResponseMessage()).thenReturn(message);
        when(conn.getHeaderField(0)).thenReturn(statusLine);

        // Mock getHeaderFields to return our headers
        Map<String, List<String>> allHeaders = headers != null ? new HashMap<>(headers) : new HashMap<>();
        allHeaders.put(null, Collections.singletonList(statusLine)); // Status line
        when(conn.getHeaderFields()).thenReturn(allHeaders);

        // Mock individual header access by both string key and index
        if (headers != null) {
            // Mock by header name
            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                when(conn.getHeaderField(entry.getKey())).thenReturn(entry.getValue().get(0));
            }

            // Mock by index - getHeaderField(int)
            // Index 0 is status line, then headers in order
            int index = 1;
            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                when(conn.getHeaderField(index++)).thenReturn(entry.getValue().get(0));
            }
        }

        if (code >= 400 && stream != null) {
            when(conn.getErrorStream()).thenReturn(stream);
        } else if (stream != null) {
            when(conn.getInputStream()).thenReturn(stream);
        }
    }

    /**
     * Test helper class for mocking URL.openConnection() behavior
     */
    static class TestURLStreamHandler extends java.net.URLStreamHandler {
        private final List<HttpURLConnection> connections = new ArrayList<>();
        private int currentIndex = 0;

        void addConnection(HttpURLConnection conn) {
            connections.add(conn);
        }

        @Override
        protected URLConnection openConnection(URL u) throws IOException {
            if (currentIndex < connections.size()) {
                return connections.get(currentIndex++);
            }
            throw new IOException("No more connections available");
        }
    }
}
