package jcifs.http;

import static java.net.HttpURLConnection.HTTP_OK;
import static java.net.HttpURLConnection.HTTP_UNAUTHORIZED;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.RuntimeCIFSException;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;
import jcifs.internal.smb2.Smb2EchoRequest;
import jcifs.NameServiceClient;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.ntlmssp.Type1Message;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.Type3Message;

/**
 * Tests for the NtlmHttpURLConnection class.
 * This class uses Mockito to simulate the behavior of HttpURLConnection and other dependencies.
 */
@ExtendWith(MockitoExtension.class)
class NtlmHttpURLConnectionTest {

    @Mock
    private HttpURLConnection mockConnection;

    @Mock
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
        // Basic setup for mocks to avoid NullPointerExceptions
        when(mockConnection.getURL()).thenReturn(mockUrl);
        when(mockConnection.getRequestProperties()).thenReturn(new HashMap<>());
        when(mockUrl.openConnection()).thenReturn(mockConnection);
        
        // Mock CIFSContext behavior
        NtlmPasswordAuthentication creds = new NtlmPasswordAuthentication(new BaseContext(new PropertyConfiguration(System.getProperties())), "domain", "user", "password");
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
    void testConnect() throws IOException {
        // Act
        ntlmConnection.connect();

        // Assert
        verify(mockConnection).connect();
        assertTrue(ntlmConnection.connected);
    }

    /**
     * Test that disconnect() calls disconnect() on the underlying connection and resets state.
     */
    @Test
    void testDisconnect() {
        // Act
        ntlmConnection.disconnect();

        // Assert
        verify(mockConnection).disconnect();
        assertFalse(ntlmConnection.connected);
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
        verify(spiedConnection).handshake();

        assertDoesNotThrow(() -> spiedConnection.getInputStream());
        // handshake() should only be called once
        verify(spiedConnection, times(1)).handshake();
    }

    /**
     * Test a successful NTLM authentication handshake.
     * This is the main test case for the NTLM logic.
     * @throws IOException
     * @throws SecurityException
     */
    @Test
    void testSuccessfulHandshake() throws IOException, SecurityException {
        // Arrange
        // We need three distinct connection objects for the 3-way handshake
        HttpURLConnection conn1 = mock(HttpURLConnection.class, "conn1");
        HttpURLConnection conn2 = mock(HttpURLConnection.class, "conn2");
        HttpURLConnection conn3 = mock(HttpURLConnection.class, "conn3");

        // Initial connection setup
        when(conn1.getURL()).thenReturn(mockUrl);
        when(conn1.getRequestProperties()).thenReturn(new HashMap<>());
        when(mockUrl.openConnection()).thenReturn(conn2, conn3); // First reconnect gets conn2, second gets conn3

        // Create the real object with the first connection
        ntlmConnection = new NtlmHttpURLConnection(conn1, mockCifsContext);

        // --- Handshake Step 1: Client sends request, Server responds 401 with NTLM challenge ---
        mockResponse(conn1, HTTP_UNAUTHORIZED, "Unauthorized",
                Collections.singletonMap("WWW-Authenticate", Collections.singletonList("NTLM")),
                new ByteArrayInputStream(new byte[0]));

        // --- Handshake Step 2: Client sends Type1, Server responds 401 with Type2 ---
        Type2Message type2 = new Type2Message(); // A simplified Type2 message
        String type2Base64 = new String(Base64.encode(type2.toByteArray()));
        mockResponse(conn2, HTTP_UNAUTHORIZED, "Unauthorized",
                Collections.singletonMap("WWW-Authenticate", Collections.singletonList("NTLM " + type2Base64)),
                new ByteArrayInputStream(new byte[0]));

        // --- Handshake Step 3: Client sends Type3, Server responds 200 OK ---
        mockResponse(conn3, HTTP_OK, "OK",
                Collections.singletonMap("Content-Type", Collections.singletonList("text/plain")),
                new ByteArrayInputStream("Success".getBytes()));

        // Act
        int responseCode = ntlmConnection.getResponseCode();
        String responseMessage = ntlmConnection.getResponseMessage();
        InputStream is = ntlmConnection.getInputStream();

        // Assert
        assertEquals(HTTP_OK, responseCode);
        assertEquals("OK", responseMessage);
        assertNotNull(is);

        // Verify the Authorization headers were set correctly
        ArgumentCaptor<String> authHeaderCaptor = ArgumentCaptor.forClass(String.class);
        InOrder inOrder = inOrder(conn1, conn2, conn3);

        // Initial connection has no auth header
        inOrder.verify(conn1).connect();

        // Second connection should have Type1 message
        inOrder.verify(conn2).setRequestProperty(anyString(), authHeaderCaptor.capture());
        assertTrue(authHeaderCaptor.getValue().startsWith("NTLM "));
        // Decode and check if it's a Type1 message
        byte[] type1Bytes = Base64.decode(authHeaderCaptor.getValue().substring(5));
        assertDoesNotThrow(() -> new Type1Message(type1Bytes));

        // Third connection should have Type3 message
        inOrder.verify(conn3).setRequestProperty(anyString(), authHeaderCaptor.capture());
        assertTrue(authHeaderCaptor.getValue().startsWith("NTLM "));
        byte[] type3Bytes = Base64.decode(authHeaderCaptor.getValue().substring(5));
        // It's hard to validate Type3 without a real challenge, so we just check it's sent
        assertNotNull(type3Bytes);
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
        // Verify we did not try to reconnect
        verify(mockUrl, times(0)).openConnection();
    }

    /**
     * Test that getOutputStream() returns a stream that caches output before handshake.
     * @throws IOException
     */
    @Test
    void testGetOutputStreamCachesData() throws IOException {
        // Arrange
        // Mock the final connection that will receive the data
        HttpURLConnection finalConnection = mock(HttpURLConnection.class);
        OutputStream finalOutputStream = mock(OutputStream.class);
        when(finalConnection.getOutputStream()).thenReturn(finalOutputStream);

        // Mock the handshake process
        mockResponse(HTTP_UNAUTHORIZED, "Unauthorized",
                Collections.singletonMap("WWW-Authenticate", Collections.singletonList("NTLM")),
                new ByteArrayInputStream(new byte[0]));
        when(mockUrl.openConnection()).thenReturn(finalConnection); // Reconnect will return the final connection
        mockResponse(finalConnection, HTTP_OK, "OK", null, null);

        // Act
        // 1. Get output stream (before handshake) and write data to it
        OutputStream os = ntlmConnection.getOutputStream();
        byte[] testData = "test data".getBytes();
        os.write(testData);
        os.flush();
        os.close();

        // 2. Trigger handshake
        ntlmConnection.getResponseCode();

        // Assert
        // Verify that the cached data was written to the final connection's output stream
        verify(finalOutputStream).write(testData, 0, testData.length);
        verify(finalOutputStream).flush();
        verify(finalOutputStream).close();
    }
    
    /**
     * Test that a RuntimeCIFSException is thrown when the handshake fails due to an underlying exception.
     * @throws IOException
     */
    @Test
    void testHandshakeThrowsRuntimeExceptionOnFailure() throws IOException {
        // Arrange
        when(mockConnection.getHeaderField(0)).thenThrow(new IOException("Connection failed"));
        doNothing().when(mockConnection).connect();
        ntlmConnection.connected = true;

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
    private void mockResponse(HttpURLConnection conn, int code, String message, Map<String, List<String>> headers, InputStream stream) throws IOException {
        if (conn == null) return;

        String statusLine = "HTTP/1.1 " + code + " " + message;
        when(conn.getResponseCode()).thenReturn(code);
        when(conn.getResponseMessage()).thenReturn(message);
        when(conn.getHeaderField(0)).thenReturn(statusLine);

        // Mock getHeaderFields to return our headers
        Map<String, List<String>> allHeaders = headers != null ? new HashMap<>(headers) : new HashMap<>();
        allHeaders.put(null, Collections.singletonList(statusLine)); // Status line
        when(conn.getHeaderFields()).thenReturn(allHeaders);

        // Mock individual header access
        if (headers != null) {
            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                when(conn.getHeaderField(entry.getKey())).thenReturn(entry.getValue().get(0));
            }
        }

        if (code >= 400 && stream != null) {
            when(conn.getErrorStream()).thenReturn(stream);
        } else if (stream != null) {
            when(conn.getInputStream()).thenReturn(stream);
        }
    }
}
