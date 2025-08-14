package jcifs.ntlmssp;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.LinkedList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.NameServiceClient;
import jcifs.NetbiosAddress;
import jcifs.ntlmssp.av.AvFlags;
import jcifs.ntlmssp.av.AvPair;
import jcifs.ntlmssp.av.AvPairs;
import jcifs.ntlmssp.av.AvSingleHost;
import jcifs.ntlmssp.av.AvTargetName;
import jcifs.ntlmssp.av.AvTimestamp;

/**
 * Test class for NTLMSSP Type 3 Message functionality
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Type3Message Tests")
class Type3MessageTest {

    @Mock
    private CIFSContext mockContext;

    @BeforeEach
    void setUp() {
        // Basic setup for mock context if needed
    }

    /**
     * Helper method to create properly configured mock context
     */
    private CIFSContext createMockContext() {
        CIFSContext mockCtx = mock(CIFSContext.class);
        Configuration mockConfig = mock(Configuration.class);
        NameServiceClient mockNameServiceClient = mock(NameServiceClient.class);
        NetbiosAddress mockHost = mock(NetbiosAddress.class);
        SecureRandom mockRandom = mock(SecureRandom.class);

        // Create a machine ID (32 bytes)
        byte[] machineId = new byte[32];
        mockRandom.nextBytes(machineId);

        lenient().when(mockConfig.getDefaultDomain()).thenReturn("TESTDOMAIN");
        lenient().when(mockConfig.isUseUnicode()).thenReturn(true);
        lenient().when(mockConfig.getOemEncoding()).thenReturn("UTF-8");
        lenient().when(mockConfig.getRandom()).thenReturn(mockRandom);
        lenient().when(mockConfig.getLanManCompatibility()).thenReturn(3); // Default NTLMv2
        lenient().when(mockConfig.getMachineId()).thenReturn(machineId);
        lenient().when(mockCtx.getConfig()).thenReturn(mockConfig);
        lenient().when(mockCtx.getNameServiceClient()).thenReturn(mockNameServiceClient);
        lenient().when(mockNameServiceClient.getLocalHost()).thenReturn(mockHost);
        lenient().when(mockHost.getHostName()).thenReturn("TEST_HOSTNAME");

        return mockCtx;
    }

    @Test
    @DisplayName("Should create Type 3 message with authentication data")
    void testType3MessageCreation() throws Exception {
        // Given
        Type2Message type2 = createMockType2Message();
        String password = "testpassword";
        String domain = "TESTDOMAIN";
        String username = "testuser";
        String workstation = "TESTWS";
        int flags = NtlmFlags.NTLMSSP_NEGOTIATE_UNICODE | NtlmFlags.NTLMSSP_NEGOTIATE_NTLM;

        // When
        Type3Message type3 = new Type3Message(createMockContext(), type2, null, password, domain, username, workstation, flags);

        // Then
        assertNotNull(type3);
        // Note: // Note: getType() method does not exist method does not exist in Type3Message
        assertEquals(domain, type3.getDomain());
        assertEquals(username, type3.getUser());
        assertEquals(workstation, type3.getWorkstation());
    }

    @Test
    @DisplayName("Should parse Type 3 message from byte array")
    void testType3MessageFromBytes() throws Exception {
        // Given - Create a Type 3 message and convert to bytes
        Type2Message type2 = createMockType2Message();
        Type3Message original = new Type3Message(createMockContext(), type2, null, "password", "DOMAIN", "user", "WORKSTATION", 0);
        byte[] messageBytes = original.toByteArray();

        // When
        Type3Message parsed = new Type3Message(messageBytes);

        // Then
        // Note: getType() method does not exist, so we cannot compare message types
        assertEquals(original.getDomain(), parsed.getDomain());
        assertEquals(original.getUser(), parsed.getUser());
        assertEquals(original.getWorkstation(), parsed.getWorkstation());
    }

    @Test
    @DisplayName("Should include NTLMSSP signature")
    void testNTLMSSPSignature() throws Exception {
        // Given
        Type2Message type2 = createMockType2Message();
        Type3Message type3 = new Type3Message(createMockContext(), type2, null, "password", "DOMAIN", "user", "WORKSTATION", 0);

        // When
        byte[] messageBytes = type3.toByteArray();

        // Then
        assertTrue(messageBytes.length >= 8);
        // NTLMSSP signature should be at the beginning
        assertEquals('N', messageBytes[0]);
        assertEquals('T', messageBytes[1]);
        assertEquals('L', messageBytes[2]);
        assertEquals('M', messageBytes[3]);
        assertEquals('S', messageBytes[4]);
        assertEquals('S', messageBytes[5]);
        assertEquals('P', messageBytes[6]);
        assertEquals(0, messageBytes[7]); // Null terminator
    }

    @Test
    @DisplayName("Should include message type indicator")
    void testMessageTypeIndicator() throws Exception {
        // Given
        Type2Message type2 = createMockType2Message();
        Type3Message type3 = new Type3Message(createMockContext(), type2, null, "password", "DOMAIN", "user", "WORKSTATION", 0);

        // When
        byte[] messageBytes = type3.toByteArray();

        // Then
        assertTrue(messageBytes.length >= 12);
        // Message type should be 3 (little endian)
        assertEquals(3, messageBytes[8] & 0xFF);
        assertEquals(0, messageBytes[9] & 0xFF);
        assertEquals(0, messageBytes[10] & 0xFF);
        assertEquals(0, messageBytes[11] & 0xFF);
    }

    @Test
    @DisplayName("Should generate LM and NTLM responses")
    void testLMAndNTLMResponses() throws Exception {
        // Given
        Type2Message type2 = createMockType2Message();
        String password = "testpassword";

        // When
        Type3Message type3 = new Type3Message(createMockContext(), type2, null, password, "DOMAIN", "user", "WORKSTATION",
                NtlmFlags.NTLMSSP_NEGOTIATE_NTLM);

        // Then
        assertNotNull(type3.getLMResponse());
        assertNotNull(type3.getNTResponse());
        assertTrue(type3.getLMResponse().length > 0);
        assertTrue(type3.getNTResponse().length > 0);
    }

    @Test
    @DisplayName("Should handle Unicode strings")
    void testUnicodeStrings() throws Exception {
        // Given
        Type2Message type2 = createMockType2Message();
        String unicodeDomain = "TËSTDØMÄIN";
        String unicodeUser = "tëstüser";
        String unicodeWorkstation = "tëstws";

        // When
        Type3Message type3 = new Type3Message(createMockContext(), type2, null, "password", unicodeDomain, unicodeUser, unicodeWorkstation,
                NtlmFlags.NTLMSSP_NEGOTIATE_UNICODE);

        // Then
        assertEquals(unicodeDomain, type3.getDomain());
        assertEquals(unicodeUser, type3.getUser());
        assertEquals(unicodeWorkstation, type3.getWorkstation());
    }

    @Test
    @DisplayName("Should handle empty credentials")
    void testEmptyCredentials() throws Exception {
        // Given
        Type2Message type2 = createMockType2Message();

        // When
        Type3Message type3 = new Type3Message(createMockContext(), type2, null, "", "", "", "", 0);

        // Then
        assertEquals("", type3.getDomain());
        assertEquals("", type3.getUser());
        assertEquals("", type3.getWorkstation());
    }

    @Test
    @DisplayName("Should handle null credentials")
    void testNullCredentials() throws Exception {
        // Given
        Type2Message type2 = createMockType2Message();

        // When
        Type3Message type3 = new Type3Message(createMockContext(), type2, null, (String) null, null, null, null, 0);

        // Then
        assertNull(type3.getDomain());
        assertNull(type3.getUser());
        assertNull(type3.getWorkstation());
    }

    @Test
    @DisplayName("Should generate session key when requested")
    void testSessionKeyGeneration() throws Exception {
        // Given
        Type2Message type2 = createMockType2Message();
        int flags = NtlmFlags.NTLMSSP_NEGOTIATE_NTLM | NtlmFlags.NTLMSSP_NEGOTIATE_KEY_EXCH
                | NtlmFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;

        // When
        // Create a mock context with LanManCompatibility level 0 or 1 to test extended session security
        CIFSContext mockCtx = createMockContextWithLanManCompat(1);
        Type3Message type3 = new Type3Message(mockCtx, type2, null, "password", "DOMAIN", "user", "WORKSTATION", flags);

        // Then
        // Master key should always be generated with extended session security or NTLMv2
        assertNotNull(type3.getMasterKey());
        assertEquals(16, type3.getMasterKey().length);
    }

    @Test
    @DisplayName("Should handle extended session security")
    void testExtendedSessionSecurity() throws Exception {
        // Given
        Type2Message type2 = createMockType2Message();
        int flags = NtlmFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | NtlmFlags.NTLMSSP_NEGOTIATE_NTLM;

        // When
        Type3Message type3 = new Type3Message(createMockContext(), type2, null, "password", "DOMAIN", "user", "WORKSTATION", flags);

        // Then
        assertNotNull(type3.getNTResponse());
        // Extended session security changes response format
        assertTrue(type3.getNTResponse().length >= 24);
    }

    @Test
    @DisplayName("Should handle NTLMv2 authentication")
    void testNTLMv2Authentication() throws Exception {
        // Given
        Type2Message type2 = createMockType2MessageWithTargetInfo();
        int flags = NtlmFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | NtlmFlags.NTLMSSP_NEGOTIATE_TARGET_INFO;

        // When
        Type3Message type3 = new Type3Message(createMockContext(), type2, null, "password", "DOMAIN", "user", "WORKSTATION", flags);

        // Then
        assertNotNull(type3.getNTResponse());
        // NTLMv2 responses are typically longer than 24 bytes when target info is present
        assertTrue(type3.getNTResponse().length > 24);
    }

    @Test
    @DisplayName("Should include MIC when supported")
    void testMICInclusion() throws Exception {
        // Given
        Type2Message type2 = createMockType2Message();
        int flags = NtlmFlags.NTLMSSP_NEGOTIATE_NTLM | NtlmFlags.NTLMSSP_NEGOTIATE_VERSION;

        // When
        Type3Message type3 = new Type3Message(createMockContext(), type2, null, "password", "DOMAIN", "user", "WORKSTATION", flags);

        // Then
        // MIC (Message Integrity Check) should be included for newer versions
        if (type3.isMICRequired()) {
            assertNotNull(type3.getMic());
            assertEquals(16, type3.getMic().length); // MIC is 16 bytes
        }
    }

    @Test
    @DisplayName("Should handle case sensitivity correctly")
    void testCaseSensitivity() throws Exception {
        // Given
        Type2Message type2 = createMockType2Message();
        String mixedCaseDomain = "TestDomain";
        String mixedCaseUser = "TestUser";

        // When
        Type3Message type3 =
                new Type3Message(createMockContext(), type2, null, "password", mixedCaseDomain, mixedCaseUser, "WORKSTATION", 0);

        // Then
        assertEquals(mixedCaseDomain, type3.getDomain());
        assertEquals(mixedCaseUser, type3.getUser());
    }

    @Test
    @DisplayName("Should handle long passwords")
    void testLongPasswords() throws Exception {
        // Given
        Type2Message type2 = createMockType2Message();
        String longPassword = createTestString(256); // Very long password

        // When/Then
        assertDoesNotThrow(() -> {
            Type3Message type3 = new Type3Message(createMockContext(), type2, null, longPassword, "DOMAIN", "user", "WORKSTATION", 0);
            assertNotNull(type3.getNTResponse());
        });
    }

    @Test
    @DisplayName("Should handle special characters in credentials")
    void testSpecialCharacters() throws Exception {
        // Given
        Type2Message type2 = createMockType2Message();
        String specialDomain = "TEST-DOMAIN_123";
        String specialUser = "test.user@domain.com";
        String specialPassword = "P@ssw0rd!#$%";

        // When
        Type3Message type3 = new Type3Message(createMockContext(), type2, null, specialPassword, specialDomain, specialUser, "WORKSTATION",
                NtlmFlags.NTLMSSP_NEGOTIATE_UNICODE);

        // Then
        assertEquals(specialDomain, type3.getDomain());
        assertEquals(specialUser, type3.getUser());
        assertNotNull(type3.getNTResponse());
    }

    @Test
    @DisplayName("Should create string representation")
    void testStringRepresentation() throws Exception {
        // Given
        Type2Message type2 = createMockType2Message();
        Type3Message type3 = new Type3Message(createMockContext(), type2, null, "password", "DOMAIN", "user", "WORKSTATION", 0);

        // When
        String stringRep = type3.toString();

        // Then
        assertNotNull(stringRep);
        assertTrue(stringRep.contains("Type3Message"));
        assertTrue(stringRep.contains("DOMAIN"));
        assertTrue(stringRep.contains("user"));
        assertTrue(stringRep.contains("WORKSTATION"));
    }

    @Test
    @DisplayName("Should handle parsing invalid message bytes")
    void testInvalidMessageBytes() {
        // Given
        byte[] invalidBytes = { 1, 2, 3, 4, 5 }; // Too short and invalid

        // When/Then
        assertThrows(IOException.class, () -> {
            new Type3Message(invalidBytes);
        });
    }

    @Test
    @DisplayName("Should handle parsing null message bytes")
    void testNullMessageBytes() {
        // When/Then
        assertThrows(NullPointerException.class, () -> {
            new Type3Message((byte[]) null);
        });
    }

    /**
     * Helper method to create a mock Type 2 message for testing
     */
    private Type2Message createMockType2Message() {
        // Create a basic Type 2 message with challenge
        byte[] challenge = new byte[8];
        new SecureRandom().nextBytes(challenge);

        int flags = NtlmFlags.NTLMSSP_NEGOTIATE_UNICODE | NtlmFlags.NTLMSSP_NEGOTIATE_NTLM;

        return new Type2Message(createMockContext(), flags, challenge, "TARGET");
    }

    /**
     * Helper method to create a test string of specified length
     */
    private String createTestString(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append((char) ('A' + (i % 26)));
        }
        return sb.toString();
    }

    /**
     * Helper method to create a mock Type 2 message with target information for NTLMv2
     */
    private Type2Message createMockType2MessageWithTargetInfo() {
        // Create a Type 2 message with challenge and target info
        byte[] challenge = new byte[8];
        new SecureRandom().nextBytes(challenge);

        int flags = NtlmFlags.NTLMSSP_NEGOTIATE_UNICODE | NtlmFlags.NTLMSSP_NEGOTIATE_NTLM | NtlmFlags.NTLMSSP_NEGOTIATE_TARGET_INFO
                | NtlmFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;

        Type2Message type2 = new Type2Message(createMockContext(), flags, challenge, "TARGET");

        // Create target information with timestamp for NTLMv2
        List<AvPair> pairs = new LinkedList<>();
        pairs.add(new AvTargetName("TARGET"));
        pairs.add(new AvTimestamp(System.currentTimeMillis()));
        pairs.add(new AvFlags(0));
        pairs.add(new AvSingleHost(new byte[48])); // Dummy single host data

        type2.setTargetInformation(AvPairs.encode(pairs));

        return type2;
    }

    /**
     * Helper method to create a mock context with specific LanMan compatibility level
     */
    private CIFSContext createMockContextWithLanManCompat(int level) {
        CIFSContext mockCtx = mock(CIFSContext.class);
        Configuration mockConfig = mock(Configuration.class);
        NameServiceClient mockNameServiceClient = mock(NameServiceClient.class);
        NetbiosAddress mockHost = mock(NetbiosAddress.class);
        SecureRandom mockRandom = mock(SecureRandom.class);

        // Create a machine ID (32 bytes)
        byte[] machineId = new byte[32];
        mockRandom.nextBytes(machineId);

        lenient().when(mockConfig.getDefaultDomain()).thenReturn("TESTDOMAIN");
        lenient().when(mockConfig.isUseUnicode()).thenReturn(true);
        lenient().when(mockConfig.getOemEncoding()).thenReturn("UTF-8");
        lenient().when(mockConfig.getRandom()).thenReturn(mockRandom);
        lenient().when(mockConfig.getLanManCompatibility()).thenReturn(level);
        lenient().when(mockConfig.getMachineId()).thenReturn(machineId);
        lenient().when(mockCtx.getConfig()).thenReturn(mockConfig);
        lenient().when(mockCtx.getNameServiceClient()).thenReturn(mockNameServiceClient);
        lenient().when(mockNameServiceClient.getLocalHost()).thenReturn(mockHost);
        lenient().when(mockHost.getHostName()).thenReturn("TEST_HOSTNAME");

        return mockCtx;
    }
}