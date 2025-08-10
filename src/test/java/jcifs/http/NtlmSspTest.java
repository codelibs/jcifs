package jcifs.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Base64;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.smb.NtlmPasswordAuthentication;

/**
 * JUnit 5 tests for the NtlmSsp class.
 * This class uses Mockito to simulate HttpServletRequest and HttpServletResponse objects.
 */
@ExtendWith(MockitoExtension.class)
public class NtlmSspTest {

    @Mock
    private CIFSContext mockCifsContext;

    @Mock
    private HttpServletRequest mockRequest;

    @Mock
    private HttpServletResponse mockResponse;

    private NtlmSsp ntlmSsp;

    // A sample challenge array
    private final byte[] challenge = new byte[] { 0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef };

    // Base64 encoded Type 1 message: NTLMSSP, Type 1, flags=0x00088207
    // Domain and workstation are empty.
    private final String type1MessageBase64 = "TlRMTVNTUAABAAAABzIAAAYABgArAAAACwALACAAAABXT1JLU1RBVElPTkRPTUFJTg==";

    // Base64 encoded Type 3 message: NTLMSSP, Type 3
    // User: "user", Domain: "DOMAIN", Workstation: "WORKSTATION"
    // LM Response and NT Response are present but empty for this test.
    private final String type3MessageBase64 = "TlRMTVNTUAADAAAAGAAYAHgAAAAYABgAiAAAAAAAAAAAAAAADgAOAEQAAAASABIAYwAAAAAAAAAAAAAAAABXAG8AcgBrAHMAdABhAHQAaQBvAG4ARABPAE0AQQBJAE4AdQBzAGUAcgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";


    @BeforeEach
    public void setUp() {
        ntlmSsp = new NtlmSsp();
    }

    /**
     * Test case for when the 'Authorization' header is missing.
     * Expects the server to respond with a 'WWW-Authenticate: NTLM' header and a 401 status.
     * @throws IOException
     */
    @Test
    public void testAuthenticate_NoAuthorizationHeader() throws IOException {
        // Setup: No "Authorization" header
        when(mockRequest.getHeader("Authorization")).thenReturn(null);

        // Execute
        NtlmPasswordAuthentication result = NtlmSsp.authenticate(mockCifsContext, mockRequest, mockResponse, challenge);

        // Verify
        assertNull(result, "Authentication result should be null");
        verify(mockResponse).setHeader("WWW-Authenticate", "NTLM");
        verify(mockResponse).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verify(mockResponse).setContentLength(0);
        verify(mockResponse).flushBuffer();
    }

    /**
     * Test case for when the 'Authorization' header contains a Type 1 NTLM message.
     * Expects the server to respond with a 'WWW-Authenticate' header containing a Type 2 message.
     * @throws IOException
     */
    @Test
    public void testAuthenticate_Type1Message() throws IOException {
        // Setup: "Authorization" header with a Type 1 message
        when(mockRequest.getHeader("Authorization")).thenReturn("NTLM " + type1MessageBase64);

        // Execute
        NtlmPasswordAuthentication result = NtlmSsp.authenticate(mockCifsContext, mockRequest, mockResponse, challenge);

        // Verify
        assertNull(result, "Authentication result should be null");

        // Capture the header value to verify its contents
        ArgumentCaptor<String> headerCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockResponse).setHeader(eq("WWW-Authenticate"), headerCaptor.capture());
        String headerValue = headerCaptor.getValue();
        assertNotNull(headerValue, "WWW-Authenticate header should be set");
        assertEquals("NTLM ", headerValue.substring(0, 5), "Header should start with 'NTLM '");

        // Decode the returned Type 2 message and check its signature and type
        byte[] type2Bytes = Base64.getDecoder().decode(headerValue.substring(5));
        assertEquals('N', (char) type2Bytes[0]);
        assertEquals('T', (char) type2Bytes[1]);
        assertEquals('L', (char) type2Bytes[2]);
        assertEquals('M', (char) type2Bytes[3]);
        assertEquals('S', (char) type2Bytes[4]);
        assertEquals('S', (char) type2Bytes[5]);
        assertEquals('P', (char) type2Bytes[6]);
        assertEquals(0, type2Bytes[7]); // Null terminator
        assertEquals(2, type2Bytes[8], "Message type should be 2"); // Type 2

        // Verify response status
        verify(mockResponse).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verify(mockResponse).setContentLength(0);
        verify(mockResponse).flushBuffer();
    }

    /**
     * Test case for when the 'Authorization' header contains a Type 3 NTLM message.
     * Expects the server to successfully authenticate the user and return NtlmPasswordAuthentication.
     * @throws IOException
     */
    @Test
    public void testAuthenticate_Type3Message() throws IOException {
        // Setup: "Authorization" header with a Type 3 message
        when(mockRequest.getHeader("Authorization")).thenReturn("NTLM " + type3MessageBase64);

        // Execute
        NtlmPasswordAuthentication result = NtlmSsp.authenticate(mockCifsContext, mockRequest, mockResponse, challenge);

        // Verify
        assertNotNull(result, "Authentication result should not be null");
        assertEquals("DOMAIN", result.getDomain());
        assertEquals("user", result.getUsername());
        assertArrayEquals(challenge, result.getChallenge());
        assertNotNull(result.getLMResponse(), "LM response should not be null");
        assertNotNull(result.getNTResponse(), "NT response should not be null");

        // Verify that the response is not modified for a successful authentication
        verify(mockResponse, never()).setHeader(anyString(), anyString());
        verify(mockResponse, never()).setStatus(any(int.class));
    }
    
    /**
     * Test case for the instance method doAuthentication.
     * It should just delegate to the static authenticate method.
     * @throws IOException
     */
    @Test
    public void testDoAuthentication() throws IOException {
        // Setup: No "Authorization" header to follow a simple path
        when(mockRequest.getHeader("Authorization")).thenReturn(null);

        // Execute
        NtlmPasswordAuthentication result = ntlmSsp.doAuthentication(mockCifsContext, mockRequest, mockResponse, challenge);

        // Verify that the behavior is the same as calling the static method directly
        assertNull(result, "Authentication result should be null");
        verify(mockResponse).setHeader("WWW-Authenticate", "NTLM");
        verify(mockResponse).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
}