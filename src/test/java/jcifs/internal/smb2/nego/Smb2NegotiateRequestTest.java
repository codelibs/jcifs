package jcifs.internal.smb2.nego;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.security.SecureRandom;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.DialectVersion;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for Smb2NegotiateRequest functionality
 */
@DisplayName("Smb2NegotiateRequest Tests")
class Smb2NegotiateRequestTest {

    private Configuration mockConfig;
    private CIFSContext mockContext;
    private SecureRandom mockRandom;
    private Smb2NegotiateRequest request;
    private byte[] testMachineId = new byte[16];
    private byte[] testSalt = new byte[32];

    @BeforeEach
    void setUp() {
        mockConfig = mock(Configuration.class);
        mockContext = mock(CIFSContext.class);
        mockRandom = mock(SecureRandom.class);
        
        // Initialize test data
        for (int i = 0; i < 16; i++) {
            testMachineId[i] = (byte) (i + 1);
        }
        for (int i = 0; i < 32; i++) {
            testSalt[i] = (byte) (i + 0x10);
        }
        
        // Default configuration for SMB 3.1.1 with encryption
        when(mockConfig.isDfsDisabled()).thenReturn(false);
        when(mockConfig.isEncryptionEnabled()).thenReturn(true);
        when(mockConfig.getMinimumVersion()).thenReturn(DialectVersion.SMB202);
        when(mockConfig.getMaximumVersion()).thenReturn(DialectVersion.SMB311);
        when(mockConfig.getMachineId()).thenReturn(testMachineId);
        when(mockConfig.getRandom()).thenReturn(mockRandom);
        when(mockContext.getConfig()).thenReturn(mockConfig);
        
        // Mock random for predictable salt generation
        doAnswer(invocation -> {
            byte[] buffer = invocation.getArgument(0);
            System.arraycopy(testSalt, 0, buffer, 0, Math.min(buffer.length, testSalt.length));
            return null;
        }).when(mockRandom).nextBytes(any(byte[].class));
    }

    @Test
    @DisplayName("Should create request with default settings")
    void testConstructorWithDefaults() {
        // When
        request = new Smb2NegotiateRequest(mockConfig, Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED);
        
        // Then
        assertNotNull(request);
        assertEquals(Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED, request.getSecurityMode());
        assertFalse(request.isSigningEnforced());
        assertTrue(request instanceof ServerMessageBlock2Request);
    }

    @Test
    @DisplayName("Should set DFS capability when enabled")
    void testDfsCapability() {
        // Given
        when(mockConfig.isDfsDisabled()).thenReturn(false);
        
        // When
        request = new Smb2NegotiateRequest(mockConfig, 0);
        
        // Then
        assertTrue((request.getCapabilities() & Smb2Constants.SMB2_GLOBAL_CAP_DFS) != 0);
    }

    @Test
    @DisplayName("Should not set DFS capability when disabled")
    void testNoDfsCapability() {
        // Given
        when(mockConfig.isDfsDisabled()).thenReturn(true);
        
        // When
        request = new Smb2NegotiateRequest(mockConfig, 0);
        
        // Then
        assertEquals(0, request.getCapabilities() & Smb2Constants.SMB2_GLOBAL_CAP_DFS);
    }

    @Test
    @DisplayName("Should set encryption capability for SMB3+")
    void testEncryptionCapabilitySmb3() {
        // Given
        when(mockConfig.isEncryptionEnabled()).thenReturn(true);
        when(mockConfig.getMaximumVersion()).thenReturn(DialectVersion.SMB300);
        
        // When
        request = new Smb2NegotiateRequest(mockConfig, 0);
        
        // Then
        assertTrue((request.getCapabilities() & Smb2Constants.SMB2_GLOBAL_CAP_ENCRYPTION) != 0);
    }

    @Test
    @DisplayName("Should not set encryption capability for SMB2")
    void testNoEncryptionCapabilitySmb2() {
        // Given
        when(mockConfig.isEncryptionEnabled()).thenReturn(true);
        when(mockConfig.getMaximumVersion()).thenReturn(DialectVersion.SMB210);
        
        // When
        request = new Smb2NegotiateRequest(mockConfig, 0);
        
        // Then
        assertEquals(0, request.getCapabilities() & Smb2Constants.SMB2_GLOBAL_CAP_ENCRYPTION);
    }

    @Test
    @DisplayName("Should not set encryption capability when disabled")
    void testNoEncryptionCapabilityWhenDisabled() {
        // Given
        when(mockConfig.isEncryptionEnabled()).thenReturn(false);
        when(mockConfig.getMaximumVersion()).thenReturn(DialectVersion.SMB311);
        
        // When
        request = new Smb2NegotiateRequest(mockConfig, 0);
        
        // Then
        assertEquals(0, request.getCapabilities() & Smb2Constants.SMB2_GLOBAL_CAP_ENCRYPTION);
    }

    @Test
    @DisplayName("Should generate correct dialect list")
    void testDialectGeneration() {
        // Given
        when(mockConfig.getMinimumVersion()).thenReturn(DialectVersion.SMB210);
        when(mockConfig.getMaximumVersion()).thenReturn(DialectVersion.SMB311);
        
        // When
        request = new Smb2NegotiateRequest(mockConfig, 0);
        
        // Then
        int[] dialects = request.getDialects();
        assertNotNull(dialects);
        assertEquals(4, dialects.length); // SMB210, SMB300, SMB302, SMB311
        assertEquals(0x0210, dialects[0]);
        assertEquals(0x0300, dialects[1]);
        assertEquals(0x0302, dialects[2]);
        assertEquals(0x0311, dialects[3]);
    }

    @Test
    @DisplayName("Should set client GUID for SMB2.1+")
    void testClientGuidSmb21() {
        // Given
        when(mockConfig.getMaximumVersion()).thenReturn(DialectVersion.SMB210);
        
        // When
        request = new Smb2NegotiateRequest(mockConfig, 0);
        
        // Then
        assertArrayEquals(testMachineId, request.getClientGuid());
    }

    @Test
    @DisplayName("Should use zero GUID for SMB2.0.2")
    void testClientGuidSmb202() {
        // Given
        when(mockConfig.getMaximumVersion()).thenReturn(DialectVersion.SMB202);
        when(mockConfig.getMinimumVersion()).thenReturn(DialectVersion.SMB202);
        
        // When
        request = new Smb2NegotiateRequest(mockConfig, 0);
        
        // Then
        byte[] guid = request.getClientGuid();
        assertNotNull(guid);
        assertEquals(16, guid.length);
        // Should be zeros (not set from machine ID)
        for (byte b : guid) {
            assertEquals(0, b);
        }
    }

    @Test
    @DisplayName("Should add negotiate contexts for SMB 3.1.1")
    void testNegotiateContextsSmb311() {
        // Given
        when(mockConfig.getMaximumVersion()).thenReturn(DialectVersion.SMB311);
        when(mockConfig.isEncryptionEnabled()).thenReturn(true);
        
        // When
        request = new Smb2NegotiateRequest(mockConfig, 0);
        
        // Then
        NegotiateContextRequest[] contexts = request.getNegotiateContexts();
        assertNotNull(contexts);
        assertEquals(2, contexts.length);
        
        // Verify preauth context
        assertTrue(contexts[0] instanceof PreauthIntegrityNegotiateContext);
        assertEquals(PreauthIntegrityNegotiateContext.NEGO_CTX_PREAUTH_TYPE, contexts[0].getContextType());
        
        // Verify encryption context
        assertTrue(contexts[1] instanceof EncryptionNegotiateContext);
        assertEquals(EncryptionNegotiateContext.NEGO_CTX_ENC_TYPE, contexts[1].getContextType());
        
        // Verify salt was generated
        assertArrayEquals(testSalt, request.getPreauthSalt());
    }

    @Test
    @DisplayName("Should add only preauth context when encryption disabled for SMB 3.1.1")
    void testNegotiateContextsSmb311NoEncryption() {
        // Given
        when(mockConfig.getMaximumVersion()).thenReturn(DialectVersion.SMB311);
        when(mockConfig.isEncryptionEnabled()).thenReturn(false);
        
        // When
        request = new Smb2NegotiateRequest(mockConfig, 0);
        
        // Then
        NegotiateContextRequest[] contexts = request.getNegotiateContexts();
        assertNotNull(contexts);
        assertEquals(1, contexts.length);
        
        // Only preauth context
        assertTrue(contexts[0] instanceof PreauthIntegrityNegotiateContext);
        assertArrayEquals(testSalt, request.getPreauthSalt());
    }

    @Test
    @DisplayName("Should not add negotiate contexts for SMB 3.0.2 and below")
    void testNoNegotiateContextsSmb302() {
        // Given
        when(mockConfig.getMaximumVersion()).thenReturn(DialectVersion.SMB302);
        
        // When
        request = new Smb2NegotiateRequest(mockConfig, 0);
        
        // Then
        NegotiateContextRequest[] contexts = request.getNegotiateContexts();
        assertNotNull(contexts);
        assertEquals(0, contexts.length);
        assertNull(request.getPreauthSalt());
    }

    @Test
    @DisplayName("Should enforce signing when required flag is set")
    void testSigningEnforced() {
        // When
        request = new Smb2NegotiateRequest(mockConfig, Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED);
        
        // Then
        assertTrue(request.isSigningEnforced());
        assertEquals(Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED, request.getSecurityMode());
    }

    @Test
    @DisplayName("Should not enforce signing when enabled flag is set")
    void testSigningNotEnforced() {
        // When
        request = new Smb2NegotiateRequest(mockConfig, Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED);
        
        // Then
        assertFalse(request.isSigningEnforced());
        assertEquals(Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED, request.getSecurityMode());
    }

    @Test
    @DisplayName("Should create correct response")
    void testCreateResponse() {
        // Given
        request = new Smb2NegotiateRequest(mockConfig, 0);
        
        // When
        Smb2NegotiateResponse response = request.createResponse(mockContext, request);
        
        // Then
        assertNotNull(response);
        assertTrue(response instanceof Smb2NegotiateResponse);
    }

    @Test
    @DisplayName("Should calculate size correctly without contexts")
    void testSizeWithoutContexts() {
        // Given
        when(mockConfig.getMaximumVersion()).thenReturn(DialectVersion.SMB302);
        request = new Smb2NegotiateRequest(mockConfig, 0);
        
        // When
        int size = request.size();
        
        // Then - Header (64) + Structure (36) + Dialects (4 * 2) = 108, padded to 8-byte boundary = 112
        assertEquals(112, size);
    }

    @Test
    @DisplayName("Should calculate size correctly with contexts")
    void testSizeWithContexts() throws Exception {
        // Given
        when(mockConfig.getMaximumVersion()).thenReturn(DialectVersion.SMB311);
        when(mockConfig.isEncryptionEnabled()).thenReturn(true);
        request = new Smb2NegotiateRequest(mockConfig, 0);
        
        // When
        int size = request.size();
        
        // Then - should include context sizes
        assertTrue(size > 112); // Bigger than without contexts
        assertEquals(0, size % 8); // Should be 8-byte aligned
    }

    @Test
    @DisplayName("Should write bytes to wire format correctly")
    void testWriteBytesWireFormat() {
        // Given
        when(mockConfig.getMaximumVersion()).thenReturn(DialectVersion.SMB302);
        when(mockConfig.getMinimumVersion()).thenReturn(DialectVersion.SMB210);
        request = new Smb2NegotiateRequest(mockConfig, Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED);
        
        byte[] buffer = new byte[512];
        
        // When
        int bytesWritten = request.writeBytesWireFormat(buffer, 0);
        
        // Then
        assertTrue(bytesWritten > 0);
        
        // Verify structure size
        assertEquals(36, SMBUtil.readInt2(buffer, 0));
        
        // Verify dialect count
        assertEquals(3, SMBUtil.readInt2(buffer, 2)); // SMB210, SMB300, SMB302
        
        // Verify security mode
        assertEquals(Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED, SMBUtil.readInt2(buffer, 4));
        
        // Verify capabilities
        int caps = SMBUtil.readInt4(buffer, 8);
        assertTrue((caps & Smb2Constants.SMB2_GLOBAL_CAP_DFS) != 0);
        
        // Verify client GUID
        byte[] guid = new byte[16];
        System.arraycopy(buffer, 12, guid, 0, 16);
        assertArrayEquals(testMachineId, guid);
        
        // Verify dialects
        assertEquals(0x0210, SMBUtil.readInt2(buffer, 36));
        assertEquals(0x0300, SMBUtil.readInt2(buffer, 38));
        assertEquals(0x0302, SMBUtil.readInt2(buffer, 40));
    }

    @Test
    @DisplayName("Should write negotiate contexts for SMB 3.1.1")
    void testWriteBytesWireFormatWithContexts() {
        // Given
        when(mockConfig.getMaximumVersion()).thenReturn(DialectVersion.SMB311);
        when(mockConfig.isEncryptionEnabled()).thenReturn(true);
        request = new Smb2NegotiateRequest(mockConfig, 0);
        
        byte[] buffer = new byte[512];
        
        // When
        int bytesWritten = request.writeBytesWireFormat(buffer, 0);
        
        // Then
        assertTrue(bytesWritten > 36);
        
        // Verify negotiate context count
        assertEquals(2, SMBUtil.readInt2(buffer, 32));
        
        // Verify negotiate context offset is set
        int contextOffset = SMBUtil.readInt4(buffer, 28);
        assertTrue(contextOffset > 0);
        
        // Skip detailed context verification since we can't access headerStart
        // Just verify that contexts were written
        assertTrue(bytesWritten > 60); // Should be larger than basic negotiate request
    }

    @Test
    @DisplayName("Should handle empty negotiate contexts array")
    void testWriteBytesWireFormatEmptyContexts() {
        // Given
        when(mockConfig.getMaximumVersion()).thenReturn(DialectVersion.SMB302);
        request = new Smb2NegotiateRequest(mockConfig, 0);
        
        byte[] buffer = new byte[512];
        
        // When
        int bytesWritten = request.writeBytesWireFormat(buffer, 0);
        
        // Then
        assertTrue(bytesWritten > 0);
        
        // Verify negotiate context offset/count area is zeroed
        assertEquals(0, SMBUtil.readInt8(buffer, 28));
    }

    @Test
    @DisplayName("Should read empty bytes from wire format")
    void testReadBytesWireFormat() {
        // Given
        request = new Smb2NegotiateRequest(mockConfig, 0);
        byte[] buffer = new byte[256];
        
        // When
        int bytesRead = request.readBytesWireFormat(buffer, 0);
        
        // Then - This is a request, so it doesn't read from wire
        assertEquals(0, bytesRead);
    }

    @ParameterizedTest
    @DisplayName("Should generate correct dialects for version ranges")
    @MethodSource("provideVersionRanges")
    void testDialectGenerationForVersionRanges(DialectVersion min, DialectVersion max, 
                                               int[] expectedDialects) {
        // Given
        when(mockConfig.getMinimumVersion()).thenReturn(min);
        when(mockConfig.getMaximumVersion()).thenReturn(max);
        
        // When
        request = new Smb2NegotiateRequest(mockConfig, 0);
        
        // Then
        assertArrayEquals(expectedDialects, request.getDialects());
    }

    private static Stream<Arguments> provideVersionRanges() {
        return Stream.of(
            Arguments.of(DialectVersion.SMB202, DialectVersion.SMB202, 
                        new int[] { 0x0202 }),
            Arguments.of(DialectVersion.SMB202, DialectVersion.SMB210, 
                        new int[] { 0x0202, 0x0210 }),
            Arguments.of(DialectVersion.SMB210, DialectVersion.SMB300, 
                        new int[] { 0x0210, 0x0300 }),
            Arguments.of(DialectVersion.SMB202, DialectVersion.SMB311, 
                        new int[] { 0x0202, 0x0210, 0x0300, 0x0302, 0x0311 }),
            Arguments.of(DialectVersion.SMB311, DialectVersion.SMB311, 
                        new int[] { 0x0311 })
        );
    }

    @ParameterizedTest
    @DisplayName("Should set capabilities based on configuration")
    @CsvSource({
        "true, true, SMB311, 2", // DFS + Encryption
        "false, true, SMB311, 1", // Encryption only
        "true, false, SMB311, 1", // DFS only
        "false, false, SMB311, 0", // Neither
        "true, true, SMB210, 1", // DFS only (no encryption for SMB2)
        "false, true, SMB210, 0"  // Neither (no encryption for SMB2)
    })
    void testCapabilitiesBasedOnConfig(boolean dfsEnabled, boolean encryptionEnabled, 
                                      String maxVersion, int expectedCapabilityCount) {
        // Given
        when(mockConfig.isDfsDisabled()).thenReturn(!dfsEnabled);
        when(mockConfig.isEncryptionEnabled()).thenReturn(encryptionEnabled);
        when(mockConfig.getMaximumVersion()).thenReturn(DialectVersion.valueOf(maxVersion));
        
        // When
        request = new Smb2NegotiateRequest(mockConfig, 0);
        
        // Then
        int caps = request.getCapabilities();
        int capCount = 0;
        if ((caps & Smb2Constants.SMB2_GLOBAL_CAP_DFS) != 0) capCount++;
        if ((caps & Smb2Constants.SMB2_GLOBAL_CAP_ENCRYPTION) != 0) capCount++;
        
        assertEquals(expectedCapabilityCount, capCount);
    }

    @Test
    @DisplayName("Should handle all getters correctly")
    void testAllGetters() {
        // Given
        when(mockConfig.getMaximumVersion()).thenReturn(DialectVersion.SMB311);
        when(mockConfig.isEncryptionEnabled()).thenReturn(true);
        
        // When
        request = new Smb2NegotiateRequest(mockConfig, Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED);
        
        // Then - Test all getters
        assertEquals(Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED, request.getSecurityMode());
        assertTrue(request.isSigningEnforced());
        assertNotNull(request.getCapabilities());
        assertNotNull(request.getDialects());
        assertNotNull(request.getClientGuid());
        assertNotNull(request.getNegotiateContexts());
        assertNotNull(request.getPreauthSalt());
        
        // Verify data integrity
        assertEquals(16, request.getClientGuid().length);
        assertEquals(32, request.getPreauthSalt().length);
        assertTrue(request.getDialects().length > 0);
        assertEquals(2, request.getNegotiateContexts().length);
    }

    @Test
    @DisplayName("Should handle minimum version greater than SMB202")
    void testMinimumVersionHigherThanSMB202() {
        // Given
        when(mockConfig.getMinimumVersion()).thenReturn(DialectVersion.SMB300);
        when(mockConfig.getMaximumVersion()).thenReturn(DialectVersion.SMB311);
        
        // When
        request = new Smb2NegotiateRequest(mockConfig, 0);
        
        // Then
        int[] dialects = request.getDialects();
        // Should not include SMB202 or SMB210
        for (int dialect : dialects) {
            assertTrue(dialect >= 0x0300);
        }
    }

    @Test
    @DisplayName("Should handle null maximum version")
    void testNullMaximumVersion() {
        // Given
        when(mockConfig.getMaximumVersion()).thenReturn(null);
        
        // When/Then - Should throw NPE based on actual implementation
        assertThrows(NullPointerException.class, () -> {
            new Smb2NegotiateRequest(mockConfig, 0);
        });
    }

    @Test
    @DisplayName("Should properly align buffer writes")
    void testBufferAlignment() {
        // Given
        when(mockConfig.getMaximumVersion()).thenReturn(DialectVersion.SMB311);
        request = new Smb2NegotiateRequest(mockConfig, 0);
        
        byte[] buffer = new byte[1024];
        
        // When
        int bytesWritten = request.writeBytesWireFormat(buffer, 0);
        
        // Then - Total bytes written should be 8-byte aligned
        assertEquals(0, bytesWritten % 8);
    }

    @ParameterizedTest
    @DisplayName("Should handle security mode combinations")
    @MethodSource("provideSecurityModes")
    void testSecurityModeCombinations(int securityMode) {
        // When
        request = new Smb2NegotiateRequest(mockConfig, securityMode);
        
        // Then
        assertEquals(securityMode, request.getSecurityMode());
        boolean shouldEnforce = (securityMode & Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED) != 0;
        assertEquals(shouldEnforce, request.isSigningEnforced());
    }
    
    private static Stream<Arguments> provideSecurityModes() {
        return Stream.of(
            Arguments.of(0),
            Arguments.of(Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED),
            Arguments.of(Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED),
            Arguments.of(Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED | Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED)
        );
    }
}