package jcifs.ntlmssp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import java.io.IOException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.NameServiceClient;
import jcifs.NetbiosAddress;

import static org.mockito.Mockito.when;

/**
 * Test class for NTLMSSP Type 1 Message functionality
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Type1Message Tests")
class Type1MessageTest {

    @Mock
    private CIFSContext mockContext;
    
    @Mock
    private Configuration mockConfig;
    
    @Mock
    private NameServiceClient mockNameServiceClient;
    
    @Mock
    private NetbiosAddress mockLocalHost;

    @BeforeEach
    void setUp() {
        // Setup mock context with lenient stubbing to avoid UnnecessaryStubbingException
        lenient().when(mockContext.getConfig()).thenReturn(mockConfig);
        lenient().when(mockContext.getNameServiceClient()).thenReturn(mockNameServiceClient);
        lenient().when(mockNameServiceClient.getLocalHost()).thenReturn(mockLocalHost);
        lenient().when(mockLocalHost.getHostName()).thenReturn("localhost");
        lenient().when(mockConfig.getDefaultDomain()).thenReturn("WORKGROUP");
        lenient().when(mockConfig.isUseUnicode()).thenReturn(true);
    }

    @Test
    @DisplayName("Should create Type 1 message with default flags")
    void testType1MessageCreation() {
        // When
        Type1Message type1 = new Type1Message(mockContext);

        // Then
        assertNotNull(type1);
        // Note: getType() method does not exist in Type1Message
        assertTrue(type1.getFlags() != 0); // Should have some flags set
    }

    @Test
    @DisplayName("Should create Type 1 message with custom flags")
    void testType1MessageWithFlags() {
        // Given
        int flags =
                NtlmFlags.NTLMSSP_NEGOTIATE_UNICODE | NtlmFlags.NTLMSSP_NEGOTIATE_NTLM | NtlmFlags.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED;

        // When
        Type1Message type1 = new Type1Message(mockContext, flags, null, null);

        // Then
        // Note: Constructor sets default flags OR'd with provided flags
        assertTrue((type1.getFlags() & flags) != 0);
        // Note: getType() method does not exist in Type1Message
    }

    @Test
    @DisplayName("Should create Type 1 message with domain and workstation")
    void testType1MessageWithDomainAndWorkstation() {
        // Given
        String domain = "TESTDOMAIN";
        String workstation = "TESTWS";
        int flags = NtlmFlags.NTLMSSP_NEGOTIATE_UNICODE | NtlmFlags.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
                | NtlmFlags.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED;

        // When
        Type1Message type1 = new Type1Message(mockContext, flags, domain, workstation);

        // Then
        assertEquals(domain, type1.getSuppliedDomain());
        assertEquals(workstation, type1.getSuppliedWorkstation());
        assertTrue((type1.getFlags() & NtlmFlags.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED) != 0);
        assertTrue((type1.getFlags() & NtlmFlags.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED) != 0);
    }

    @Test
    @DisplayName("Should parse Type 1 message from byte array")
    void testType1MessageFromBytes() throws IOException {
        // Given - Create a Type 1 message and convert to bytes
        Type1Message original = new Type1Message(mockContext);
        byte[] messageBytes = original.toByteArray();

        // When
        Type1Message parsed = new Type1Message(messageBytes);

        // Then
        // Note: getType() method does not exist in Type1Message
        assertEquals(original.getFlags(), parsed.getFlags());
    }

    @ParameterizedTest
    @ValueSource(ints = { NtlmFlags.NTLMSSP_NEGOTIATE_UNICODE, NtlmFlags.NTLMSSP_NEGOTIATE_OEM, NtlmFlags.NTLMSSP_NEGOTIATE_NTLM,
            NtlmFlags.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED, NtlmFlags.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED })
    @DisplayName("Should handle various NTLM flags")
    void testVariousNTLMFlags(int flag) {
        // When
        Type1Message type1 = new Type1Message(mockContext, flag, null, null);

        // Then
        assertTrue((type1.getFlags() & flag) != 0);
    }

    @Test
    @DisplayName("Should include NTLMSSP signature")
    void testNTLMSSPSignature() throws IOException {
        // When
        Type1Message type1 = new Type1Message(mockContext);
        byte[] messageBytes = type1.toByteArray();

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
    void testMessageTypeIndicator() throws IOException {
        // When
        Type1Message type1 = new Type1Message(mockContext);
        byte[] messageBytes = type1.toByteArray();

        // Then
        assertTrue(messageBytes.length >= 12);
        // Message type should be 1 (little endian)
        assertEquals(1, messageBytes[8] & 0xFF);
        assertEquals(0, messageBytes[9] & 0xFF);
        assertEquals(0, messageBytes[10] & 0xFF);
        assertEquals(0, messageBytes[11] & 0xFF);
    }

    @Test
    @DisplayName("Should handle Unicode negotiation flag")
    void testUnicodeNegotiation() {
        // Given
        int unicodeFlags = NtlmFlags.NTLMSSP_NEGOTIATE_UNICODE;
        int oemFlags = NtlmFlags.NTLMSSP_NEGOTIATE_OEM;

        // When
        Type1Message unicodeType1 = new Type1Message(mockContext, unicodeFlags, null, null);
        Type1Message oemType1 = new Type1Message(mockContext, oemFlags, null, null);

        // Then
        assertTrue((unicodeType1.getFlags() & NtlmFlags.NTLMSSP_NEGOTIATE_UNICODE) != 0);
        assertFalse((unicodeType1.getFlags() & NtlmFlags.NTLMSSP_NEGOTIATE_OEM) != 0);

        assertTrue((oemType1.getFlags() & NtlmFlags.NTLMSSP_NEGOTIATE_OEM) != 0);
        assertFalse((oemType1.getFlags() & NtlmFlags.NTLMSSP_NEGOTIATE_UNICODE) != 0);
    }

    @Test
    @DisplayName("Should handle NTLM version negotiation")
    void testNTLMVersionNegotiation() {
        // Given
        int ntlmFlags = NtlmFlags.NTLMSSP_NEGOTIATE_NTLM;

        // When
        Type1Message type1 = new Type1Message(mockContext, ntlmFlags, null, null);

        // Then
        assertTrue((type1.getFlags() & NtlmFlags.NTLMSSP_NEGOTIATE_NTLM) != 0);
    }

    @Test
    @DisplayName("Should handle empty domain and workstation")
    void testEmptyDomainAndWorkstation() {
        // Given
        String emptyDomain = "";
        String emptyWorkstation = "";

        // When
        Type1Message type1 = new Type1Message(mockContext, 0, emptyDomain, emptyWorkstation);

        // Then
        assertEquals(emptyDomain, type1.getSuppliedDomain());
        assertEquals(emptyWorkstation, type1.getSuppliedWorkstation());
    }

    @Test
    @DisplayName("Should handle null domain and workstation")
    void testNullDomainAndWorkstation() {
        // When
        Type1Message type1 = new Type1Message(mockContext, 0, null, null);

        // Then
        assertNull(type1.getSuppliedDomain());
        assertNull(type1.getSuppliedWorkstation());
    }

    @Test
    @DisplayName("Should handle case sensitivity in domain and workstation")
    void testCaseSensitivity() {
        // Given
        String domain = "TestDomain";
        String workstation = "TestWorkstation";

        // When
        Type1Message type1 = new Type1Message(mockContext, 0, domain, workstation);

        // Then
        assertEquals(domain, type1.getSuppliedDomain());
        assertEquals(workstation, type1.getSuppliedWorkstation());
    }

    @Test
    @DisplayName("Should generate consistent byte representation")
    void testConsistentByteRepresentation() throws IOException {
        // Given
        Type1Message type1 = new Type1Message(mockContext);

        // When
        byte[] bytes1 = type1.toByteArray();
        byte[] bytes2 = type1.toByteArray();

        // Then
        assertArrayEquals(bytes1, bytes2);
    }

    @Test
    @DisplayName("Should handle parsing invalid message bytes")
    void testInvalidMessageBytes() {
        // Given
        byte[] invalidBytes = { 1, 2, 3, 4, 5 }; // Too short and invalid

        // When/Then
        assertThrows(IOException.class, () -> {
            new Type1Message(invalidBytes);
        });
    }

    @Test
    @DisplayName("Should handle parsing null message bytes")
    void testNullMessageBytes() {
        // When/Then
        assertThrows(NullPointerException.class, () -> {
            new Type1Message((byte[]) null);
        });
    }

    @Test
    @DisplayName("Should create string representation")
    void testStringRepresentation() {
        // Given
        Type1Message type1 = new Type1Message(mockContext, NtlmFlags.NTLMSSP_NEGOTIATE_UNICODE, "DOMAIN", "WORKSTATION");

        // When
        String stringRep = type1.toString();

        // Then
        assertNotNull(stringRep);
        assertTrue(stringRep.contains("Type1Message"));
        assertTrue(stringRep.contains("DOMAIN"));
        assertTrue(stringRep.contains("WORKSTATION"));
    }

    @Test
    @DisplayName("Should handle extended security flags")
    void testExtendedSecurityFlags() {
        // Given
        int extendedFlags = NtlmFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;

        // When
        Type1Message type1 = new Type1Message(mockContext, extendedFlags, null, null);

        // Then
        assertTrue((type1.getFlags() & NtlmFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) != 0);
    }

    @Test
    @DisplayName("Should handle target info flags")
    void testTargetInfoFlags() {
        // Given
        int targetInfoFlags = NtlmFlags.NTLMSSP_NEGOTIATE_TARGET_INFO;

        // When
        Type1Message type1 = new Type1Message(mockContext, targetInfoFlags, null, null);

        // Then
        assertTrue((type1.getFlags() & NtlmFlags.NTLMSSP_NEGOTIATE_TARGET_INFO) != 0);
    }
}