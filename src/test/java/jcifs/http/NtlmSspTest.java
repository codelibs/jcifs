package jcifs.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.UnknownHostException;
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
import jcifs.Configuration;
import jcifs.NameServiceClient;
import jcifs.NetbiosAddress;
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
    private Configuration mockConfig;

    @Mock
    private NameServiceClient mockNameServiceClient;

    @Mock
    private NetbiosAddress mockAddress;

    @Mock
    private HttpServletRequest mockRequest;

    @Mock
    private HttpServletResponse mockResponse;

    private NtlmSsp ntlmSsp;

    // A sample challenge array
    private final byte[] challenge = new byte[] { 0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef };

    // Base64 encoded Type 1 message: NTLMSSP, Type 1, flags=0x00088207
    // Domain="DOMAIN", Workstation="WORKSTATION"
    private final String type1MessageBase64 = "TlRMTVNTUAABAAAABzIAAAYABgArAAAACwALACAAAABET01BSU5XT1JLU1RBVElPTg==";

    // Base64 encoded Type 3 message: NTLMSSP, Type 3
    // User: "user", Domain: "DOMAIN", Workstation: "WORKSTATION"
    // This is a valid Type 3 message with proper structure
    private final String type3MessageBase64 = createValidType3Message();

    /**
     * Creates a valid Type 3 NTLM message for testing
     */
    private static String createValidType3Message() {
        // Build a properly formatted Type 3 message
        byte[] message = new byte[200];

        // NTLMSSP signature
        System.arraycopy("NTLMSSP\0".getBytes(), 0, message, 0, 8);

        // Type 3 indicator
        message[8] = 0x03;

        // LM Response (24 bytes at offset 64)
        message[12] = 24; // Length
        message[13] = 0;
        message[14] = 24; // Max Length
        message[15] = 0;
        message[16] = 64; // Offset
        message[17] = 0;
        message[18] = 0;
        message[19] = 0;

        // NT Response (24 bytes at offset 88)
        message[20] = 24; // Length
        message[21] = 0;
        message[22] = 24; // Max Length
        message[23] = 0;
        message[24] = 88; // Offset
        message[25] = 0;
        message[26] = 0;
        message[27] = 0;

        // Domain (12 bytes "DOMAIN" in Unicode at offset 112)
        message[28] = 12; // Length
        message[29] = 0;
        message[30] = 12; // Max Length
        message[31] = 0;
        message[32] = 112; // Offset
        message[33] = 0;
        message[34] = 0;
        message[35] = 0;

        // User (8 bytes "user" in Unicode at offset 124)
        message[36] = 8; // Length
        message[37] = 0;
        message[38] = 8; // Max Length
        message[39] = 0;
        message[40] = 124; // Offset
        message[41] = 0;
        message[42] = 0;
        message[43] = 0;

        // Workstation (22 bytes "WORKSTATION" in Unicode at offset 132)
        message[44] = 22; // Length
        message[45] = 0;
        message[46] = 22; // Max Length
        message[47] = 0;
        message[48] = (byte) 132; // Offset
        message[49] = 0;
        message[50] = 0;
        message[51] = 0;

        // Session Key (empty, offset 154)
        message[52] = 0; // Length
        message[53] = 0;
        message[54] = 0; // Max Length
        message[55] = 0;
        message[56] = (byte) 154; // Offset
        message[57] = 0;
        message[58] = 0;
        message[59] = 0;

        // Flags (NTLMSSP_NEGOTIATE_UNICODE)
        message[60] = 0x01; // NTLMSSP_NEGOTIATE_UNICODE
        message[61] = 0x00;
        message[62] = 0x00;
        message[63] = 0x00;

        // Add dummy LM response (24 zeros at offset 64)
        for (int i = 0; i < 24; i++) {
            message[64 + i] = 0;
        }

        // Add dummy NT response (24 zeros at offset 88)
        for (int i = 0; i < 24; i++) {
            message[88 + i] = 0;
        }

        // Add Domain "DOMAIN" in Unicode at offset 112
        String domain = "DOMAIN";
        byte[] domainBytes = domain.getBytes();
        for (int i = 0; i < domainBytes.length; i++) {
            message[112 + i * 2] = domainBytes[i];
            message[112 + i * 2 + 1] = 0;
        }

        // Add User "user" in Unicode at offset 124
        String user = "user";
        byte[] userBytes = user.getBytes();
        for (int i = 0; i < userBytes.length; i++) {
            message[124 + i * 2] = userBytes[i];
            message[124 + i * 2 + 1] = 0;
        }

        // Add Workstation "WORKSTATION" in Unicode at offset 132
        String workstation = "WORKSTATION";
        byte[] workstationBytes = workstation.getBytes();
        for (int i = 0; i < workstationBytes.length; i++) {
            message[132 + i * 2] = workstationBytes[i];
            message[132 + i * 2 + 1] = 0;
        }

        // Total message length is 154 bytes
        byte[] finalMessage = new byte[154];
        System.arraycopy(message, 0, finalMessage, 0, 154);

        return Base64.getEncoder().encodeToString(finalMessage);
    }

    @BeforeEach
    public void setUp() throws UnknownHostException {
        ntlmSsp = new NtlmSsp();

        // Use lenient stubbing to avoid UnnecessaryStubbing errors for tests that don't need all mocks
        lenient().when(mockCifsContext.getConfig()).thenReturn(mockConfig);
        lenient().when(mockConfig.getDefaultDomain()).thenReturn("DOMAIN");
        lenient().when(mockConfig.isUseUnicode()).thenReturn(true);

        // Mock NameServiceClient for Type1Message test
        lenient().when(mockCifsContext.getNameServiceClient()).thenReturn(mockNameServiceClient);
        lenient().when(mockNameServiceClient.getLocalHost()).thenReturn(mockAddress);
        lenient().when(mockAddress.getHostName()).thenReturn("WORKSTATION");
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
        assertEquals("DOMAIN", result.getUserDomain());
        assertEquals("user", result.getUsername());
        // Cannot verify challenge and responses as they are not exposed in the API

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