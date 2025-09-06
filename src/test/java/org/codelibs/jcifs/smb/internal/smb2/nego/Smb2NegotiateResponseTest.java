package org.codelibs.jcifs.smb.internal.smb2.nego;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.stream.Stream;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlock;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.SmbNegotiationResponse;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Response;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.codelibs.jcifs.smb.util.transport.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Test class for Smb2NegotiateResponse functionality
 */
@DisplayName("Smb2NegotiateResponse Tests")
class Smb2NegotiateResponseTest {

    private Configuration mockConfig;
    private CIFSContext mockContext;
    private Smb2NegotiateResponse response;
    private Smb2NegotiateRequest mockRequest;

    @BeforeEach
    void setUp() {
        mockConfig = mock(Configuration.class);
        mockContext = mock(CIFSContext.class);
        mockRequest = mock(Smb2NegotiateRequest.class);
        response = new Smb2NegotiateResponse(mockConfig);

        // Default configuration
        when(mockConfig.isDfsDisabled()).thenReturn(false);
        when(mockConfig.isEncryptionEnabled()).thenReturn(true);
        when(mockConfig.getMinimumVersion()).thenReturn(DialectVersion.SMB202);
        when(mockConfig.getMaximumVersion()).thenReturn(DialectVersion.SMB311);
        when(mockConfig.getTransactionBufferSize()).thenReturn(65536);
        when(mockConfig.getReceiveBufferSize()).thenReturn(65536);
        when(mockConfig.getSendBufferSize()).thenReturn(65536);
        when(mockContext.getConfig()).thenReturn(mockConfig);
    }

    @Test
    @DisplayName("Should create response with configuration")
    void testConstructor() {
        // When
        Smb2NegotiateResponse resp = new Smb2NegotiateResponse(mockConfig);

        // Then
        assertNotNull(resp);
        assertTrue(resp instanceof ServerMessageBlock2Response);
        assertTrue(resp instanceof SmbNegotiationResponse);
    }

    @Test
    @DisplayName("Should return initial credits from getCredit")
    void testGetInitialCredits() throws Exception {
        // Given - set credit using reflection
        Field creditField = ServerMessageBlock2.class.getDeclaredField("credit");
        creditField.setAccessible(true);
        creditField.set(response, 128);

        // When
        int credits = response.getInitialCredits();

        // Then
        assertEquals(128, credits);
    }

    @Test
    @DisplayName("Should return dialect revision")
    void testGetDialectRevision() throws Exception {
        // Given
        setPrivateField(response, "dialectRevision", 0x0311);

        // When
        int dialect = response.getDialectRevision();

        // Then
        assertEquals(0x0311, dialect);
    }

    @Test
    @DisplayName("Should return server GUID")
    void testGetServerGuid() throws Exception {
        // Given
        byte[] guid = new byte[16];
        for (int i = 0; i < 16; i++) {
            guid[i] = (byte) i;
        }
        setPrivateField(response, "serverGuid", guid);

        // When
        byte[] result = response.getServerGuid();

        // Then
        assertArrayEquals(guid, result);
    }

    @Test
    @DisplayName("Should return selected dialect")
    void testGetSelectedDialect() throws Exception {
        // Given
        setPrivateField(response, "selectedDialect", DialectVersion.SMB311);

        // When
        DialectVersion dialect = response.getSelectedDialect();

        // Then
        assertEquals(DialectVersion.SMB311, dialect);
    }

    @Test
    @DisplayName("Should return selected cipher")
    void testGetSelectedCipher() throws Exception {
        // Given
        setPrivateField(response, "selectedCipher", EncryptionNegotiateContext.CIPHER_AES128_GCM);

        // When
        int cipher = response.getSelectedCipher();

        // Then
        assertEquals(EncryptionNegotiateContext.CIPHER_AES128_GCM, cipher);
    }

    @Test
    @DisplayName("Should return selected preauth hash")
    void testGetSelectedPreauthHash() throws Exception {
        // Given
        setPrivateField(response, "selectedPreauthHash", PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512);

        // When
        int hash = response.getSelectedPreauthHash();

        // Then
        assertEquals(PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512, hash);
    }

    @Test
    @DisplayName("Should return capabilities")
    void testGetCapabilities() throws Exception {
        // Given
        setPrivateField(response, "capabilities", 0x7F);

        // When
        int caps = response.getCapabilities();

        // Then
        assertEquals(0x7F, caps);
    }

    @Test
    @DisplayName("Should return common capabilities")
    void testGetCommonCapabilities() throws Exception {
        // Given
        setPrivateField(response, "commonCapabilities", 0x3F);

        // When
        int caps = response.getCommonCapabilities();

        // Then
        assertEquals(0x3F, caps);
    }

    @Test
    @DisplayName("Should return security blob")
    void testGetSecurityBlob() throws Exception {
        // Given
        byte[] blob = "SecurityBlob".getBytes();
        setPrivateField(response, "securityBuffer", blob);

        // When
        byte[] result = response.getSecurityBlob();

        // Then
        assertArrayEquals(blob, result);
    }

    @Test
    @DisplayName("Should return max transact size")
    void testGetMaxTransactSize() throws Exception {
        // Given
        setPrivateField(response, "maxTransactSize", 1048576);

        // When
        int size = response.getMaxTransactSize();

        // Then
        assertEquals(1048576, size);
    }

    @Test
    @DisplayName("Should return transaction buffer size")
    void testGetTransactionBufferSize() throws Exception {
        // Given
        setPrivateField(response, "maxTransactSize", 65536);

        // When
        int size = response.getTransactionBufferSize();

        // Then
        assertEquals(65536, size);
    }

    @Test
    @DisplayName("Should return negotiate contexts")
    void testGetNegotiateContexts() throws Exception {
        // Given
        NegotiateContextResponse[] contexts = new NegotiateContextResponse[2];
        contexts[0] = new EncryptionNegotiateContext();
        contexts[1] = new PreauthIntegrityNegotiateContext();
        setPrivateField(response, "negotiateContexts", contexts);

        // When
        NegotiateContextResponse[] result = response.getNegotiateContexts();

        // Then
        assertSame(contexts, result);
    }

    @Test
    @DisplayName("Should return server start time")
    void testGetServerStartTime() throws Exception {
        // Given
        long startTime = System.currentTimeMillis();
        setPrivateField(response, "serverStartTime", startTime);

        // When
        long result = response.getServerStartTime();

        // Then
        assertEquals(startTime, result);
    }

    @Test
    @DisplayName("Should return security mode")
    void testGetSecurityMode() throws Exception {
        // Given
        setPrivateField(response, "securityMode", Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED);

        // When
        int mode = response.getSecurityMode();

        // Then
        assertEquals(Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED, mode);
    }

    @Test
    @DisplayName("Should check capability correctly")
    void testHaveCapability() throws Exception {
        // Given
        setPrivateField(response, "commonCapabilities", 0x2F); // 0010 1111

        // Then
        assertTrue(response.haveCapabilitiy(0x01)); // Has this bit
        assertTrue(response.haveCapabilitiy(0x0F)); // Has all these bits
        assertFalse(response.haveCapabilitiy(0x10)); // Doesn't have this bit
        assertFalse(response.haveCapabilitiy(0x40)); // Doesn't have this bit
    }

    @Test
    @DisplayName("Should check DFS support correctly")
    void testIsDFSSupported() throws Exception {
        // Test with DFS capability enabled
        setPrivateField(response, "commonCapabilities", Smb2Constants.SMB2_GLOBAL_CAP_DFS);
        when(mockConfig.isDfsDisabled()).thenReturn(false);
        assertTrue(response.isDFSSupported());

        // Test with DFS disabled in config
        when(mockConfig.isDfsDisabled()).thenReturn(true);
        assertFalse(response.isDFSSupported());

        // Test without DFS capability
        when(mockConfig.isDfsDisabled()).thenReturn(false);
        setPrivateField(response, "commonCapabilities", 0);
        assertFalse(response.isDFSSupported());
    }

    @Test
    @DisplayName("Should check encryption support")
    void testIsEncryptionSupported() throws Exception {
        // Given
        setPrivateField(response, "supportsEncryption", true);

        // Then
        assertTrue(response.isEncryptionSupported());

        // Given
        setPrivateField(response, "supportsEncryption", false);

        // Then
        assertFalse(response.isEncryptionSupported());
    }

    @Test
    @DisplayName("Should check if can reuse")
    void testCanReuse() {
        // When same config
        assertTrue(response.canReuse(mockContext, false));

        // When different config
        Configuration otherConfig = mock(Configuration.class);
        CIFSContext otherContext = mock(CIFSContext.class);
        when(otherContext.getConfig()).thenReturn(otherConfig);
        assertFalse(response.canReuse(otherContext, false));
    }

    @Test
    @DisplayName("Should validate response correctly")
    void testIsValid() throws Exception {
        // Setup valid response
        setResponseAsReceived(response);
        setPrivateField(response, "dialectRevision", 0x0311);
        setPrivateField(response, "securityMode", Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED);
        setPrivateField(response, "capabilities", Smb2Constants.SMB2_GLOBAL_CAP_DFS);
        setPrivateField(response, "maxReadSize", 65536);
        setPrivateField(response, "maxWriteSize", 65536);
        setPrivateField(response, "maxTransactSize", 65536);

        // Setup valid request
        when(mockRequest.isSigningEnforced()).thenReturn(false);
        when(mockRequest.getCapabilities()).thenReturn(Smb2Constants.SMB2_GLOBAL_CAP_DFS);
        when(mockRequest.getNegotiateContexts())
                .thenReturn(new NegotiateContextRequest[] { createMockPreauthContext(), createMockEncryptionContext() });

        // Setup negotiate contexts
        NegotiateContextResponse[] contexts =
                new NegotiateContextResponse[] { createValidPreauthResponse(), createValidEncryptionResponse() };
        setPrivateField(response, "negotiateContexts", contexts);

        // When
        boolean valid = response.isValid(mockContext, mockRequest);

        // Then
        assertTrue(valid);
        assertEquals(DialectVersion.SMB311, response.getSelectedDialect());
    }

    @Test
    @DisplayName("Should fail validation when not received")
    void testIsValidNotReceived() {
        // When
        boolean valid = response.isValid(mockContext, mockRequest);

        // Then
        assertFalse(valid);
    }

    @Test
    @DisplayName("Should fail validation when signing enforced but not enabled")
    void testIsValidSigningEnforcedButNotEnabled() throws Exception {
        // Given
        setResponseAsReceived(response);
        when(mockRequest.isSigningEnforced()).thenReturn(true);
        setPrivateField(response, "securityMode", 0); // No signing

        // When
        boolean valid = response.isValid(mockContext, mockRequest);

        // Then
        assertFalse(valid);
    }

    @Test
    @DisplayName("Should fail validation with ANY dialect")
    void testIsValidAnyDialect() throws Exception {
        // Given
        setResponseAsReceived(response);
        setPrivateField(response, "dialectRevision", Smb2Constants.SMB2_DIALECT_ANY);

        // When
        boolean valid = response.isValid(mockContext, mockRequest);

        // Then
        assertFalse(valid);
    }

    @Test
    @DisplayName("Should fail validation with unknown dialect")
    void testIsValidUnknownDialect() throws Exception {
        // Given
        setResponseAsReceived(response);
        setPrivateField(response, "dialectRevision", 0x9999); // Unknown dialect

        // When
        boolean valid = response.isValid(mockContext, mockRequest);

        // Then
        assertFalse(valid);
    }

    @Test
    @DisplayName("Should fail validation with disallowed dialect")
    void testIsValidDisallowedDialect() throws Exception {
        // Given
        setResponseAsReceived(response);
        setPrivateField(response, "dialectRevision", 0x0202); // SMB 2.0.2
        when(mockConfig.getMinimumVersion()).thenReturn(DialectVersion.SMB210);

        // When
        boolean valid = response.isValid(mockContext, mockRequest);

        // Then
        assertFalse(valid);
    }

    @Test
    @DisplayName("Should check signing correctly")
    void testSigningMethods() throws Exception {
        // Test signing enabled
        setPrivateField(response, "securityMode", Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED);
        assertTrue(response.isSigningEnabled());
        assertFalse(response.isSigningRequired());
        assertFalse(response.isSigningNegotiated());

        // Test signing required
        setPrivateField(response, "securityMode", Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED);
        assertFalse(response.isSigningEnabled());
        assertTrue(response.isSigningRequired());
        assertTrue(response.isSigningNegotiated());

        // Test both flags
        setPrivateField(response, "securityMode",
                Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED | Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED);
        assertTrue(response.isSigningEnabled());
        assertTrue(response.isSigningRequired());
        assertTrue(response.isSigningNegotiated());
    }

    @Test
    @DisplayName("Should return receive buffer size")
    void testGetReceiveBufferSize() throws Exception {
        // Given
        setPrivateField(response, "maxReadSize", 131072);

        // When
        int size = response.getReceiveBufferSize();

        // Then
        assertEquals(131072, size);
    }

    @Test
    @DisplayName("Should return send buffer size")
    void testGetSendBufferSize() throws Exception {
        // Given
        setPrivateField(response, "maxWriteSize", 131072);

        // When
        int size = response.getSendBufferSize();

        // Then
        assertEquals(131072, size);
    }

    @Test
    @DisplayName("Should setup request correctly")
    void testSetupRequest() {
        // Given
        CommonServerMessageBlock request = mock(CommonServerMessageBlock.class);

        // When
        response.setupRequest(request);

        // Then - nothing should happen (empty implementation)
        verifyNoInteractions(request);
    }

    @Test
    @DisplayName("Should setup response correctly")
    void testSetupResponse() {
        // Given
        Response resp = mock(Response.class);

        // When
        response.setupResponse(resp);

        // Then - nothing should happen (empty implementation)
        verifyNoInteractions(resp);
    }

    @Test
    @DisplayName("Should read valid negotiate response from wire format")
    void testReadBytesWireFormatValid() throws Exception {
        // Given
        byte[] buffer = createValidNegotiateResponseBuffer();

        // When
        int bytesRead = response.readBytesWireFormat(buffer, 0);

        // Then
        assertTrue(bytesRead > 0);
        assertEquals(Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED, response.getSecurityMode());
        assertEquals(0x0311, response.getDialectRevision());
        assertNotNull(response.getServerGuid());
    }

    @ParameterizedTest
    @DisplayName("Should throw exception for invalid structure size")
    @ValueSource(ints = { 0, 1, 64, 66, 128 })
    void testReadBytesWireFormatInvalidStructureSize(int structureSize) {
        // Given
        byte[] buffer = new byte[256];
        SMBUtil.writeInt2(structureSize, buffer, 0);

        // When & Then
        assertThrows(SMBProtocolDecodingException.class, () -> response.readBytesWireFormat(buffer, 0), "Structure size is not 65");
    }

    @Test
    @DisplayName("Should read negotiate contexts for SMB 3.1.1")
    void testReadBytesWireFormatWithNegotiateContexts() throws Exception {
        // Given
        byte[] buffer = createValidNegotiateResponseBufferWithContexts();

        // When
        int bytesRead = response.readBytesWireFormat(buffer, 0);

        // Then
        assertTrue(bytesRead > 65);
        assertNotNull(response.getNegotiateContexts());
        assertEquals(2, response.getNegotiateContexts().length);
    }

    @Test
    @DisplayName("Should write empty bytes to wire format")
    void testWriteBytesWireFormat() {
        // Given
        byte[] buffer = new byte[256];

        // When
        int bytesWritten = response.writeBytesWireFormat(buffer, 0);

        // Then
        assertEquals(0, bytesWritten);
    }

    @Test
    @DisplayName("Should create correct context types")
    void testCreateContext() {
        // Test encryption context
        NegotiateContextResponse enc = Smb2NegotiateResponse.createContext(EncryptionNegotiateContext.NEGO_CTX_ENC_TYPE);
        assertNotNull(enc);
        assertTrue(enc instanceof EncryptionNegotiateContext);

        // Test preauth context
        NegotiateContextResponse preauth = Smb2NegotiateResponse.createContext(PreauthIntegrityNegotiateContext.NEGO_CTX_PREAUTH_TYPE);
        assertNotNull(preauth);
        assertTrue(preauth instanceof PreauthIntegrityNegotiateContext);

        // Test unknown context
        NegotiateContextResponse unknown = Smb2NegotiateResponse.createContext(0x9999);
        assertNull(unknown);
    }

    @Test
    @DisplayName("Should generate correct toString")
    void testToString() throws Exception {
        // Given
        setPrivateField(response, "dialectRevision", 0x0311);
        setPrivateField(response, "securityMode", 0x01);
        setPrivateField(response, "capabilities", 0x7F);
        setPrivateField(response, "systemTime", System.currentTimeMillis());

        // When
        String str = response.toString();

        // Then
        assertNotNull(str);
        assertTrue(str.contains("Smb2NegotiateResponse"));
        assertTrue(str.contains("dialectRevision="));
        assertTrue(str.contains("securityMode="));
        assertTrue(str.contains("capabilities="));
        assertTrue(str.contains("serverTime="));
    }

    @Test
    @DisplayName("Should validate negotiate contexts correctly for SMB 3.1.1")
    void testCheckNegotiateContexts() throws Exception {
        // Given valid response with contexts
        setResponseAsReceived(response);
        setPrivateField(response, "dialectRevision", 0x0311);
        setPrivateField(response, "capabilities", Smb2Constants.SMB2_GLOBAL_CAP_ENCRYPTION);

        when(mockRequest.getCapabilities()).thenReturn(Smb2Constants.SMB2_GLOBAL_CAP_ENCRYPTION);
        when(mockRequest.getNegotiateContexts())
                .thenReturn(new NegotiateContextRequest[] { createMockPreauthContext(), createMockEncryptionContext() });

        NegotiateContextResponse[] contexts =
                new NegotiateContextResponse[] { createValidPreauthResponse(), createValidEncryptionResponse() };
        setPrivateField(response, "negotiateContexts", contexts);

        // When
        boolean valid = response.isValid(mockContext, mockRequest);

        // Then
        assertTrue(valid);
        assertEquals(EncryptionNegotiateContext.CIPHER_AES128_GCM, response.getSelectedCipher());
        assertEquals(PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512, response.getSelectedPreauthHash());
    }

    @Test
    @DisplayName("Should fail validation with missing negotiate contexts for SMB 3.1.1")
    void testMissingNegotiateContexts() throws Exception {
        // Given
        setResponseAsReceived(response);
        setPrivateField(response, "dialectRevision", 0x0311);
        when(mockRequest.getCapabilities()).thenReturn(0);

        // When
        boolean valid = response.isValid(mockContext, mockRequest);

        // Then
        assertFalse(valid);
    }

    @Test
    @DisplayName("Should fail validation with duplicate preauth contexts")
    void testDuplicatePreauthContexts() throws Exception {
        // Given
        setResponseAsReceived(response);
        setPrivateField(response, "dialectRevision", 0x0311);

        NegotiateContextResponse[] contexts = new NegotiateContextResponse[] { createValidPreauthResponse(), createValidPreauthResponse() // Duplicate
        };
        setPrivateField(response, "negotiateContexts", contexts);

        when(mockRequest.getCapabilities()).thenReturn(0);
        when(mockRequest.getNegotiateContexts()).thenReturn(new NegotiateContextRequest[] { createMockPreauthContext() });

        // When
        boolean valid = response.isValid(mockContext, mockRequest);

        // Then
        assertFalse(valid);
    }

    @Test
    @DisplayName("Should fail validation with duplicate encryption contexts")
    void testDuplicateEncryptionContexts() throws Exception {
        // Given
        setResponseAsReceived(response);
        setPrivateField(response, "dialectRevision", 0x0311);
        setPrivateField(response, "capabilities", Smb2Constants.SMB2_GLOBAL_CAP_ENCRYPTION);

        NegotiateContextResponse[] contexts = new NegotiateContextResponse[] { createValidPreauthResponse(),
                createValidEncryptionResponse(), createValidEncryptionResponse() // Duplicate
        };
        setPrivateField(response, "negotiateContexts", contexts);

        when(mockRequest.getCapabilities()).thenReturn(Smb2Constants.SMB2_GLOBAL_CAP_ENCRYPTION);
        when(mockRequest.getNegotiateContexts())
                .thenReturn(new NegotiateContextRequest[] { createMockPreauthContext(), createMockEncryptionContext() });

        // When
        boolean valid = response.isValid(mockContext, mockRequest);

        // Then
        assertFalse(valid);
    }

    @Test
    @DisplayName("Should handle null negotiate contexts")
    void testNullNegotiateContexts() throws Exception {
        // Given
        setResponseAsReceived(response);
        setPrivateField(response, "dialectRevision", 0x0311);

        NegotiateContextResponse[] contexts = new NegotiateContextResponse[] { null, createValidPreauthResponse(), null };
        setPrivateField(response, "negotiateContexts", contexts);

        when(mockRequest.getCapabilities()).thenReturn(0);
        when(mockRequest.getNegotiateContexts()).thenReturn(new NegotiateContextRequest[] { createMockPreauthContext() });

        // When
        boolean valid = response.isValid(mockContext, mockRequest);

        // Then
        assertTrue(valid);
    }

    @Test
    @DisplayName("Should calculate buffer sizes correctly")
    void testBufferSizeCalculations() throws Exception {
        // Given
        setResponseAsReceived(response);
        setPrivateField(response, "dialectRevision", 0x0300);
        setPrivateField(response, "maxReadSize", 1048576);
        setPrivateField(response, "maxWriteSize", 1048576);
        setPrivateField(response, "maxTransactSize", 1048576);

        when(mockConfig.getTransactionBufferSize()).thenReturn(65536);
        when(mockConfig.getReceiveBufferSize()).thenReturn(32768);
        when(mockConfig.getSendBufferSize()).thenReturn(32768);
        when(mockRequest.getCapabilities()).thenReturn(0);

        // When
        boolean valid = response.isValid(mockContext, mockRequest);

        // Then
        assertTrue(valid);
        // Should be aligned to 8-byte boundary
        assertEquals(32768 & ~0x7, response.getReceiveBufferSize());
        assertEquals(32768 & ~0x7, response.getSendBufferSize());
        assertTrue(response.getTransactionBufferSize() <= 65536);
    }

    @ParameterizedTest
    @DisplayName("Should validate different dialect versions")
    @MethodSource("provideDialectVersions")
    void testDifferentDialectVersions(int dialectValue, DialectVersion expectedDialect, boolean shouldBeValid) throws Exception {
        // Given
        setResponseAsReceived(response);
        setPrivateField(response, "dialectRevision", dialectValue);
        when(mockRequest.getCapabilities()).thenReturn(0);

        // For SMB 3.1.1, we need negotiate contexts
        if (dialectValue == 0x0311) {
            NegotiateContextResponse[] contexts = new NegotiateContextResponse[] { createValidPreauthResponse() };
            setPrivateField(response, "negotiateContexts", contexts);
            when(mockRequest.getNegotiateContexts()).thenReturn(new NegotiateContextRequest[] { createMockPreauthContext() });
        }

        // When
        boolean valid = response.isValid(mockContext, mockRequest);

        // Then
        assertEquals(shouldBeValid, valid);
        if (shouldBeValid) {
            assertEquals(expectedDialect, response.getSelectedDialect());
        }
    }

    private static Stream<Arguments> provideDialectVersions() {
        return Stream.of(Arguments.of(0x0202, DialectVersion.SMB202, true), Arguments.of(0x0210, DialectVersion.SMB210, true),
                Arguments.of(0x0300, DialectVersion.SMB300, true), Arguments.of(0x0302, DialectVersion.SMB302, true),
                Arguments.of(0x0311, DialectVersion.SMB311, true), Arguments.of(0xFFFF, null, false), // SMB2_DIALECT_ANY
                Arguments.of(0x9999, null, false) // Unknown dialect
        );
    }

    // Helper methods

    private void setPrivateField(Object target, String fieldName, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }

    private void setResponseAsReceived(Smb2NegotiateResponse resp) throws Exception {
        Method setReceivedMethod = ServerMessageBlock2Response.class.getDeclaredMethod("received");
        setReceivedMethod.setAccessible(true);
        setReceivedMethod.invoke(resp);
    }

    private byte[] createValidNegotiateResponseBuffer() {
        byte[] buffer = new byte[256];
        int offset = 0;

        // Structure size (65)
        SMBUtil.writeInt2(65, buffer, offset);

        // Security mode
        SMBUtil.writeInt2(Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED, buffer, offset + 2);

        // Dialect revision
        SMBUtil.writeInt2(0x0311, buffer, offset + 4);

        // Negotiate context count
        SMBUtil.writeInt2(0, buffer, offset + 6);

        // Server GUID (16 bytes)
        for (int i = 0; i < 16; i++) {
            buffer[offset + 8 + i] = (byte) i;
        }

        // Capabilities
        SMBUtil.writeInt4(Smb2Constants.SMB2_GLOBAL_CAP_DFS, buffer, offset + 24);

        // Max transact size
        SMBUtil.writeInt4(1048576, buffer, offset + 28);

        // Max read size
        SMBUtil.writeInt4(1048576, buffer, offset + 32);

        // Max write size
        SMBUtil.writeInt4(1048576, buffer, offset + 36);

        // System time
        SMBUtil.writeTime(System.currentTimeMillis(), buffer, offset + 40);

        // Server start time
        SMBUtil.writeTime(System.currentTimeMillis() - 3600000, buffer, offset + 48);

        // Security buffer offset and length
        SMBUtil.writeInt2(128, buffer, offset + 56); // Offset
        SMBUtil.writeInt2(0, buffer, offset + 58); // Length

        // Negotiate context offset
        SMBUtil.writeInt4(0, buffer, offset + 60);

        return buffer;
    }

    private byte[] createValidNegotiateResponseBufferWithContexts() {
        byte[] buffer = new byte[512];
        int offset = 0;

        // Structure size (65)
        SMBUtil.writeInt2(65, buffer, offset);

        // Security mode
        SMBUtil.writeInt2(Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED, buffer, offset + 2);

        // Dialect revision
        SMBUtil.writeInt2(0x0311, buffer, offset + 4);

        // Negotiate context count
        SMBUtil.writeInt2(2, buffer, offset + 6);

        // Server GUID (16 bytes)
        for (int i = 0; i < 16; i++) {
            buffer[offset + 8 + i] = (byte) i;
        }

        // Capabilities
        SMBUtil.writeInt4(Smb2Constants.SMB2_GLOBAL_CAP_DFS | Smb2Constants.SMB2_GLOBAL_CAP_ENCRYPTION, buffer, offset + 24);

        // Max transact size
        SMBUtil.writeInt4(1048576, buffer, offset + 28);

        // Max read size
        SMBUtil.writeInt4(1048576, buffer, offset + 32);

        // Max write size
        SMBUtil.writeInt4(1048576, buffer, offset + 36);

        // System time
        SMBUtil.writeTime(System.currentTimeMillis(), buffer, offset + 40);

        // Server start time
        SMBUtil.writeTime(System.currentTimeMillis() - 3600000, buffer, offset + 48);

        // Security buffer offset and length
        SMBUtil.writeInt2(128, buffer, offset + 56); // Offset
        SMBUtil.writeInt2(0, buffer, offset + 58); // Length

        // Negotiate context offset
        SMBUtil.writeInt4(144, buffer, offset + 60); // Point to contexts

        // Add negotiate contexts at offset 144
        int ctxOffset = 144;

        // Preauth integrity context
        SMBUtil.writeInt2(PreauthIntegrityNegotiateContext.NEGO_CTX_PREAUTH_TYPE, buffer, ctxOffset);
        SMBUtil.writeInt2(38, buffer, ctxOffset + 2); // Data length
        ctxOffset += 8; // Skip reserved

        // Hash algorithm count and salt length
        SMBUtil.writeInt2(1, buffer, ctxOffset);
        SMBUtil.writeInt2(32, buffer, ctxOffset + 2);
        SMBUtil.writeInt2(PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512, buffer, ctxOffset + 4);
        ctxOffset += 6;

        // Salt (32 bytes)
        for (int i = 0; i < 32; i++) {
            buffer[ctxOffset + i] = (byte) i;
        }
        ctxOffset += 32;

        // Padding for 8-byte alignment
        ctxOffset = (ctxOffset + 7) & ~7;

        // Encryption context
        SMBUtil.writeInt2(EncryptionNegotiateContext.NEGO_CTX_ENC_TYPE, buffer, ctxOffset);
        SMBUtil.writeInt2(4, buffer, ctxOffset + 2); // Data length
        ctxOffset += 8; // Skip reserved

        // Cipher count and cipher
        SMBUtil.writeInt2(1, buffer, ctxOffset);
        SMBUtil.writeInt2(EncryptionNegotiateContext.CIPHER_AES128_GCM, buffer, ctxOffset + 2);

        return buffer;
    }

    private NegotiateContextRequest createMockPreauthContext() {
        PreauthIntegrityNegotiateContext ctx = new PreauthIntegrityNegotiateContext();
        try {
            setPrivateField(ctx, "hashAlgos", new int[] { PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512 });
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return ctx;
    }

    private NegotiateContextRequest createMockEncryptionContext() {
        EncryptionNegotiateContext ctx = new EncryptionNegotiateContext();
        try {
            setPrivateField(ctx, "ciphers",
                    new int[] { EncryptionNegotiateContext.CIPHER_AES128_GCM, EncryptionNegotiateContext.CIPHER_AES128_CCM });
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return ctx;
    }

    private PreauthIntegrityNegotiateContext createValidPreauthResponse() {
        PreauthIntegrityNegotiateContext ctx = new PreauthIntegrityNegotiateContext();
        try {
            setPrivateField(ctx, "hashAlgos", new int[] { PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512 });
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return ctx;
    }

    private EncryptionNegotiateContext createValidEncryptionResponse() {
        EncryptionNegotiateContext ctx = new EncryptionNegotiateContext();
        try {
            setPrivateField(ctx, "ciphers", new int[] { EncryptionNegotiateContext.CIPHER_AES128_GCM });
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return ctx;
    }
}