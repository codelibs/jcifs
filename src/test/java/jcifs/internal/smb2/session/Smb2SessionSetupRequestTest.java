package jcifs.internal.smb2.session;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jcifs.BaseTest;
import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.smb2.ServerMessageBlock2;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for Smb2SessionSetupRequest functionality
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Smb2SessionSetupRequest Tests")
@MockitoSettings(strictness = Strictness.LENIENT)
class Smb2SessionSetupRequestTest extends BaseTest {

    private Configuration mockConfig;
    private CIFSContext mockContext;
    private Smb2SessionSetupRequest request;

    // Test constants
    private static final int TEST_SECURITY_MODE = 0x01;
    private static final int TEST_CAPABILITIES = 0x00000001;
    private static final long TEST_PREVIOUS_SESSION_ID = 0x1234567890ABCDEFL;
    private static final byte[] TEST_TOKEN = { 0x01, 0x02, 0x03, 0x04, 0x05 };

    @BeforeEach
    void setUp() {
        mockConfig = mock(Configuration.class);
        mockContext = mock(CIFSContext.class);
        when(mockContext.getConfig()).thenReturn(mockConfig);
        request = new Smb2SessionSetupRequest(mockContext, TEST_SECURITY_MODE, TEST_CAPABILITIES, TEST_PREVIOUS_SESSION_ID, TEST_TOKEN);
    }

    @Test
    @DisplayName("Should create request with correct parameters")
    void testConstructorSetsCorrectParameters() throws Exception {
        // Given & When
        int securityMode = 0x03;
        int capabilities = 0x0F;
        long previousSessionId = 0xFEDCBA9876543210L;
        byte[] token = { 0x0A, 0x0B, 0x0C };

        Smb2SessionSetupRequest req = new Smb2SessionSetupRequest(mockContext, securityMode, capabilities, previousSessionId, token);

        // Then - verify fields are set correctly using reflection
        Field commandField = ServerMessageBlock2.class.getDeclaredField("command");
        commandField.setAccessible(true);
        int command = (int) commandField.get(req);
        assertEquals(0x0001, command); // SMB2_SESSION_SETUP command value

        Field securityModeField = Smb2SessionSetupRequest.class.getDeclaredField("securityMode");
        securityModeField.setAccessible(true);
        assertEquals(securityMode, securityModeField.get(req));

        Field capabilitiesField = Smb2SessionSetupRequest.class.getDeclaredField("capabilities");
        capabilitiesField.setAccessible(true);
        assertEquals(capabilities, capabilitiesField.get(req));

        Field previousSessionIdField = Smb2SessionSetupRequest.class.getDeclaredField("previousSessionId");
        previousSessionIdField.setAccessible(true);
        assertEquals(previousSessionId, previousSessionIdField.get(req));

        Field tokenField = Smb2SessionSetupRequest.class.getDeclaredField("token");
        tokenField.setAccessible(true);
        assertArrayEquals(token, (byte[]) tokenField.get(req));
    }

    @Test
    @DisplayName("Should create proper response object")
    void testCreateResponse() {
        // When
        Smb2SessionSetupResponse response = request.createResponse(mockContext, request);

        // Then
        assertNotNull(response);
        assertTrue(response instanceof Smb2SessionSetupResponse);
        // The constructor calls getConfig once, createResponse calls it once
        verify(mockContext, times(2)).getConfig();
    }

    @Test
    @DisplayName("Should set session binding flag correctly")
    void testSetSessionBinding() throws Exception {
        // Given
        Field sessionBindingField = Smb2SessionSetupRequest.class.getDeclaredField("sessionBinding");
        sessionBindingField.setAccessible(true);

        // When
        request.setSessionBinding(true);

        // Then
        assertTrue((boolean) sessionBindingField.get(request));

        // When
        request.setSessionBinding(false);

        // Then
        assertFalse((boolean) sessionBindingField.get(request));
    }

    @Test
    @DisplayName("Should handle chain operation correctly")
    void testChain() {
        // Given
        ServerMessageBlock2 nextMessage = mock(ServerMessageBlock2.class);

        // When
        boolean result = request.chain(nextMessage);

        // Then
        verify(nextMessage).setSessionId(Smb2Constants.UNSPECIFIED_SESSIONID);
        assertTrue(result); // Assuming superclass chain returns true
    }

    @Test
    @DisplayName("Should calculate correct message size with token")
    void testSizeWithToken() {
        // Given
        byte[] token = new byte[100];
        Smb2SessionSetupRequest req =
                new Smb2SessionSetupRequest(mockContext, TEST_SECURITY_MODE, TEST_CAPABILITIES, TEST_PREVIOUS_SESSION_ID, token);

        // When
        int size = req.size();

        // Then
        int expectedSize = Smb2Constants.SMB2_HEADER_LENGTH + 24 + token.length;
        int alignedSize = (expectedSize + 7) & ~7; // size8 alignment
        assertEquals(alignedSize, size);
    }

    @Test
    @DisplayName("Should calculate correct message size without token")
    void testSizeWithoutToken() {
        // Given
        Smb2SessionSetupRequest req =
                new Smb2SessionSetupRequest(mockContext, TEST_SECURITY_MODE, TEST_CAPABILITIES, TEST_PREVIOUS_SESSION_ID, null);

        // When
        int size = req.size();

        // Then
        int expectedSize = Smb2Constants.SMB2_HEADER_LENGTH + 24;
        int alignedSize = (expectedSize + 7) & ~7; // size8 alignment
        assertEquals(alignedSize, size);
    }

    @Test
    @DisplayName("Should write correct bytes to wire format with session binding")
    void testWriteBytesWireFormatWithSessionBinding() throws Exception {
        // Given
        request.setSessionBinding(true);
        byte[] buffer = new byte[512];
        int headerStart = 50;

        // Encode the full message to set headerStart
        request.encode(buffer, headerStart);

        // Then - verify the body was written correctly
        int bodyOffset = headerStart + Smb2Constants.SMB2_HEADER_LENGTH;

        // Verify structure size (25)
        assertEquals(25, SMBUtil.readInt2(buffer, bodyOffset));

        // Verify session binding flag (0x1)
        assertEquals(0x1, buffer[bodyOffset + 2]);

        // Verify security mode
        assertEquals(TEST_SECURITY_MODE, buffer[bodyOffset + 3]);

        // Verify capabilities
        assertEquals(TEST_CAPABILITIES, SMBUtil.readInt4(buffer, bodyOffset + 4));

        // Verify channel (should be 0)
        assertEquals(0, SMBUtil.readInt4(buffer, bodyOffset + 8));

        // Verify token length
        assertEquals(TEST_TOKEN.length, SMBUtil.readInt2(buffer, bodyOffset + 14));

        // Verify previous session ID
        assertEquals(TEST_PREVIOUS_SESSION_ID, SMBUtil.readInt8(buffer, bodyOffset + 16));

        // Verify token content at the security buffer offset
        int securityBufferOffset = SMBUtil.readInt2(buffer, bodyOffset + 12);
        byte[] actualToken = new byte[TEST_TOKEN.length];
        System.arraycopy(buffer, headerStart + securityBufferOffset, actualToken, 0, TEST_TOKEN.length);
        assertArrayEquals(TEST_TOKEN, actualToken);
    }

    @Test
    @DisplayName("Should write correct bytes to wire format without session binding")
    void testWriteBytesWireFormatWithoutSessionBinding() throws Exception {
        // Given
        request.setSessionBinding(false);
        byte[] buffer = new byte[512];
        int headerStart = 0;

        // Encode the full message
        request.encode(buffer, headerStart);

        // Then
        int bodyOffset = Smb2Constants.SMB2_HEADER_LENGTH;

        // Verify session binding flag (0x0)
        assertEquals(0x0, buffer[bodyOffset + 2]);
    }

    @Test
    @DisplayName("Should handle null token correctly")
    void testWriteBytesWireFormatWithNullToken() throws Exception {
        // Given
        Smb2SessionSetupRequest req =
                new Smb2SessionSetupRequest(mockContext, TEST_SECURITY_MODE, TEST_CAPABILITIES, TEST_PREVIOUS_SESSION_ID, null);
        byte[] buffer = new byte[512];

        // When
        req.encode(buffer, 0);

        // Then
        int bodyOffset = Smb2Constants.SMB2_HEADER_LENGTH;

        // Verify token length is 0
        assertEquals(0, SMBUtil.readInt2(buffer, bodyOffset + 14));
    }

    @Test
    @DisplayName("Should handle empty token correctly")
    void testWriteBytesWireFormatWithEmptyToken() throws Exception {
        // Given
        byte[] emptyToken = new byte[0];
        Smb2SessionSetupRequest req =
                new Smb2SessionSetupRequest(mockContext, TEST_SECURITY_MODE, TEST_CAPABILITIES, TEST_PREVIOUS_SESSION_ID, emptyToken);
        byte[] buffer = new byte[512];

        // When
        req.encode(buffer, 0);

        // Then
        int bodyOffset = Smb2Constants.SMB2_HEADER_LENGTH;

        // Verify token length is 0
        assertEquals(0, SMBUtil.readInt2(buffer, bodyOffset + 14));
    }

    @Test
    @DisplayName("Should always return 0 for readBytesWireFormat")
    void testReadBytesWireFormat() {
        // Given
        byte[] buffer = createTestData(256);

        // When
        int bytesRead = request.readBytesWireFormat(buffer, 0);

        // Then
        assertEquals(0, bytesRead);
    }

    @ParameterizedTest
    @ValueSource(ints = { 0, 10, 50, 100, 200, 500, 1000 })
    @DisplayName("Should handle various token sizes")
    void testVariousTokenSizes(int tokenSize) throws Exception {
        // Given
        byte[] token = createTestData(tokenSize);
        Smb2SessionSetupRequest req =
                new Smb2SessionSetupRequest(mockContext, TEST_SECURITY_MODE, TEST_CAPABILITIES, TEST_PREVIOUS_SESSION_ID, token);
        byte[] buffer = new byte[2048];

        // When
        req.encode(buffer, 0);

        // Then
        int bodyOffset = Smb2Constants.SMB2_HEADER_LENGTH;

        // Verify token length
        assertEquals(tokenSize, SMBUtil.readInt2(buffer, bodyOffset + 14));

        if (tokenSize > 0) {
            // Verify token content
            int tokenOffset = bodyOffset + 24;
            while ((tokenOffset % 8) != 0) {
                tokenOffset++; // Account for pad8
            }
            byte[] actualToken = new byte[tokenSize];
            System.arraycopy(buffer, tokenOffset, actualToken, 0, tokenSize);
            assertArrayEquals(token, actualToken);
        }
    }

    @ParameterizedTest
    @CsvSource({ "0x00, 0x00000000", "0x01, 0x00000001", "0x03, 0x0000000F", "0xFF, 0x7FFFFFFF" })
    @DisplayName("Should handle various security modes and capabilities")
    void testVariousSecurityModesAndCapabilities(String securityModeHex, String capabilitiesHex) throws Exception {
        // Given
        int securityMode = Integer.decode(securityModeHex);
        int capabilities = (int) Long.parseLong(capabilitiesHex.substring(2), 16);
        Smb2SessionSetupRequest req = new Smb2SessionSetupRequest(mockContext, securityMode, capabilities, 0, null);
        byte[] buffer = new byte[512];

        // When
        req.encode(buffer, 0);

        // Then
        int bodyOffset = Smb2Constants.SMB2_HEADER_LENGTH;
        assertEquals(securityMode, buffer[bodyOffset + 3] & 0xFF);
        assertEquals(capabilities, SMBUtil.readInt4(buffer, bodyOffset + 4));
    }

    @Test
    @DisplayName("Should write correct security buffer offset")
    void testSecurityBufferOffset() throws Exception {
        // Given
        byte[] buffer = new byte[512];

        // When
        request.encode(buffer, 0);

        // Then
        int bodyOffset = Smb2Constants.SMB2_HEADER_LENGTH;
        int securityBufferOffset = SMBUtil.readInt2(buffer, bodyOffset + 12);

        // The offset should point to the location after the fixed structure (relative to header start)
        int expectedOffset = Smb2Constants.SMB2_HEADER_LENGTH + 24;
        while ((expectedOffset % 8) != 0) {
            expectedOffset++; // Account for pad8
        }
        assertEquals(expectedOffset, securityBufferOffset);
    }

    @Test
    @DisplayName("Should handle large token correctly")
    void testLargeToken() throws Exception {
        // Given
        byte[] largeToken = createTestData(4096);
        Smb2SessionSetupRequest req =
                new Smb2SessionSetupRequest(mockContext, TEST_SECURITY_MODE, TEST_CAPABILITIES, TEST_PREVIOUS_SESSION_ID, largeToken);
        byte[] buffer = new byte[8192];

        // When
        req.encode(buffer, 0);

        // Then
        int bodyOffset = Smb2Constants.SMB2_HEADER_LENGTH;
        assertEquals(largeToken.length, SMBUtil.readInt2(buffer, bodyOffset + 14));

        // Verify token content
        int tokenOffset = bodyOffset + 24;
        while ((tokenOffset % 8) != 0) {
            tokenOffset++; // Account for pad8
        }
        byte[] actualToken = new byte[largeToken.length];
        System.arraycopy(buffer, tokenOffset, actualToken, 0, largeToken.length);
        assertArrayEquals(largeToken, actualToken);
    }

    @Test
    @DisplayName("Should correctly inherit from ServerMessageBlock2Request")
    void testInheritance() {
        // Then
        assertTrue(request instanceof ServerMessageBlock2Request);
        assertTrue(request instanceof ServerMessageBlock2);
    }

    @Test
    @DisplayName("Should handle different previous session IDs")
    void testDifferentPreviousSessionIds() throws Exception {
        // Given
        long[] sessionIds = { 0L, 1L, Long.MAX_VALUE, Long.MIN_VALUE, 0xFFFFFFFFFFFFFFFFL };

        for (long sessionId : sessionIds) {
            Smb2SessionSetupRequest req = new Smb2SessionSetupRequest(mockContext, TEST_SECURITY_MODE, TEST_CAPABILITIES, sessionId, null);
            byte[] buffer = new byte[512];

            // When
            req.encode(buffer, 0);

            // Then
            int bodyOffset = Smb2Constants.SMB2_HEADER_LENGTH;
            assertEquals(sessionId, SMBUtil.readInt8(buffer, bodyOffset + 16));
        }
    }

    @Test
    @DisplayName("Should verify padding calculation")
    void testPaddingCalculation() throws Exception {
        // Given - Create request with token
        byte[] token = new byte[5]; // Non-8-aligned size
        Smb2SessionSetupRequest req =
                new Smb2SessionSetupRequest(mockContext, TEST_SECURITY_MODE, TEST_CAPABILITIES, TEST_PREVIOUS_SESSION_ID, token);

        // Use reflection to access pad8 method
        Method pad8Method = ServerMessageBlock2.class.getDeclaredMethod("pad8", int.class);
        pad8Method.setAccessible(true);

        // Test various positions
        int[] positions = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16 };
        for (int pos : positions) {
            int padding = (int) pad8Method.invoke(req, pos);

            // Verify padding makes position 8-byte aligned
            assertEquals(0, (pos + padding) % 8);
        }
    }

    @Test
    @DisplayName("Should write bytes at different buffer offsets")
    void testWriteBytesAtDifferentOffsets() throws Exception {
        // Test at different offsets
        int[] offsets = { 0, 10, 50, 100, 200 };

        for (int offset : offsets) {
            // Given
            byte[] buffer = new byte[1024];
            Smb2SessionSetupRequest req =
                    new Smb2SessionSetupRequest(mockContext, TEST_SECURITY_MODE, TEST_CAPABILITIES, TEST_PREVIOUS_SESSION_ID, TEST_TOKEN);

            // When
            req.encode(buffer, offset);

            // Then
            int bodyOffset = offset + Smb2Constants.SMB2_HEADER_LENGTH;
            assertEquals(25, SMBUtil.readInt2(buffer, bodyOffset)); // Structure size
            assertEquals(TEST_SECURITY_MODE, buffer[bodyOffset + 3] & 0xFF); // Security mode
            assertEquals(TEST_CAPABILITIES, SMBUtil.readInt4(buffer, bodyOffset + 4)); // Capabilities
            assertEquals(TEST_TOKEN.length, SMBUtil.readInt2(buffer, bodyOffset + 14)); // Token length
        }
    }

    @Test
    @DisplayName("Should write channel field as zero")
    void testChannelFieldAlwaysZero() throws Exception {
        // Given
        byte[] buffer = new byte[512];

        // When
        request.encode(buffer, 0);

        // Then
        int bodyOffset = Smb2Constants.SMB2_HEADER_LENGTH;
        assertEquals(0, SMBUtil.readInt4(buffer, bodyOffset + 8)); // Channel field should always be 0
    }

    @Test
    @DisplayName("Should handle configuration with null context")
    void testCreateResponseWithNullConfigFromContext() {
        // Given
        CIFSContext nullConfigContext = mock(CIFSContext.class);
        when(nullConfigContext.getConfig()).thenReturn(null);

        // When
        Smb2SessionSetupResponse response = request.createResponse(nullConfigContext, request);

        // Then
        assertNotNull(response);
        assertTrue(response instanceof Smb2SessionSetupResponse);
    }

    @Test
    @DisplayName("Should verify complete wire format structure")
    void testCompleteWireFormatStructure() throws Exception {
        // Given
        int securityMode = 0x03;
        int capabilities = 0x0000000F;
        long previousSessionId = 0x123456789ABCDEF0L;
        byte[] token = { (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88 };

        Smb2SessionSetupRequest req = new Smb2SessionSetupRequest(mockContext, securityMode, capabilities, previousSessionId, token);
        req.setSessionBinding(true);
        byte[] buffer = new byte[512];

        // When
        req.encode(buffer, 0);

        // Then - Verify complete structure
        int bodyOffset = Smb2Constants.SMB2_HEADER_LENGTH;

        // Structure size
        assertEquals(25, SMBUtil.readInt2(buffer, bodyOffset));

        // Flags (VcNumber) and SecurityMode
        assertEquals(0x01, buffer[bodyOffset + 2] & 0xFF); // Session binding flag
        assertEquals(securityMode, buffer[bodyOffset + 3] & 0xFF);

        // Capabilities
        assertEquals(capabilities, SMBUtil.readInt4(buffer, bodyOffset + 4));

        // Channel
        assertEquals(0, SMBUtil.readInt4(buffer, bodyOffset + 8));

        // Security Buffer Offset
        int securityBufferOffset = SMBUtil.readInt2(buffer, bodyOffset + 12);
        assertTrue(securityBufferOffset > 0);

        // Security Buffer Length
        assertEquals(token.length, SMBUtil.readInt2(buffer, bodyOffset + 14));

        // Previous Session ID
        assertEquals(previousSessionId, SMBUtil.readInt8(buffer, bodyOffset + 16));

        // Token content
        byte[] actualToken = new byte[token.length];
        System.arraycopy(buffer, securityBufferOffset, actualToken, 0, token.length);
        assertArrayEquals(token, actualToken);
    }

    @Test
    @DisplayName("Should test writeBytesWireFormat directly")
    void testWriteBytesWireFormatDirect() throws Exception {
        // Given
        byte[] buffer = new byte[512];
        int offset = 100;

        // First encode to set headerStart
        byte[] tempBuffer = new byte[512];
        request.encode(tempBuffer, 50);

        // When
        int bytesWritten = request.writeBytesWireFormat(buffer, offset);

        // Then
        // The writeBytesWireFormat writes the structure and calculates padding
        // Base structure: 24 bytes, then pad8 alignment, then token: 5 bytes
        // Total bytes written includes padding for 8-byte alignment
        int expectedBytesWritten = 35;
        assertEquals(expectedBytesWritten, bytesWritten);

        // Verify structure
        assertEquals(25, SMBUtil.readInt2(buffer, offset)); // Structure size
        assertEquals(TEST_SECURITY_MODE, buffer[offset + 3] & 0xFF); // Security mode
        assertEquals(TEST_CAPABILITIES, SMBUtil.readInt4(buffer, offset + 4)); // Capabilities
    }

    @Test
    @DisplayName("Should handle session binding scenarios")
    void testSessionBindingScenarios() throws Exception {
        // Test both true and false session binding
        boolean[] bindingValues = { true, false };

        for (boolean binding : bindingValues) {
            // Given
            Smb2SessionSetupRequest req =
                    new Smb2SessionSetupRequest(mockContext, TEST_SECURITY_MODE, TEST_CAPABILITIES, TEST_PREVIOUS_SESSION_ID, null);
            req.setSessionBinding(binding);
            byte[] buffer = new byte[512];

            // When
            req.encode(buffer, 0);

            // Then
            int bodyOffset = Smb2Constants.SMB2_HEADER_LENGTH;
            int expectedFlag = binding ? 0x01 : 0x00;
            assertEquals(expectedFlag, buffer[bodyOffset + 2]);
        }
    }
}
