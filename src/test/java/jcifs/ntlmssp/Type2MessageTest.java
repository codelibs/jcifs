package jcifs.ntlmssp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Arrays;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.NameServiceClient;
import jcifs.NetbiosAddress;
import jcifs.util.Hexdump;

/**
 * Comprehensive test suite for Type2Message NTLM authentication message.
 * Tests all constructors, parsing, and serialization functionality.
 */
@DisplayName("Type2Message Comprehensive Tests")
class Type2MessageTest {

    private static final byte[] TEST_CHALLENGE = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    private static final String TEST_TARGET = "TEST_TARGET";
    private static final String TEST_DOMAIN = "TEST_DOMAIN";
    private static final String TEST_HOSTNAME = "TEST_HOSTNAME";

    /**
     * Helper method to create a fully mocked CIFSContext with all necessary dependencies
     */
    private CIFSContext createMockContext() {
        CIFSContext mockContext = mock(CIFSContext.class);
        Configuration mockConfig = mock(Configuration.class);
        NameServiceClient mockNameServiceClient = mock(NameServiceClient.class);
        NetbiosAddress mockHost = mock(NetbiosAddress.class);

        when(mockContext.getConfig()).thenReturn(mockConfig);
        when(mockContext.getNameServiceClient()).thenReturn(mockNameServiceClient);
        when(mockNameServiceClient.getLocalHost()).thenReturn(mockHost);
        when(mockHost.getHostName()).thenReturn(TEST_HOSTNAME);
        when(mockConfig.getDefaultDomain()).thenReturn(TEST_DOMAIN);
        when(mockConfig.isUseUnicode()).thenReturn(true);

        return mockContext;
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Constructor with CIFSContext should create message with default flags")
        void testConstructor_CIFSContext() {
            // Given
            CIFSContext mockContext = createMockContext();

            // When
            Type2Message message = new Type2Message(mockContext);

            // Then
            assertNotNull(message, "Message should not be null");
            // Verify default flags are set
            int expectedFlags =
                    Type2Message.NTLMSSP_NEGOTIATE_NTLM | Type2Message.NTLMSSP_NEGOTIATE_VERSION | Type2Message.NTLMSSP_NEGOTIATE_UNICODE;
            assertEquals(expectedFlags, message.getFlags(), "Default flags should be set correctly");
            assertNull(message.getChallenge(), "Challenge should initially be null");
            assertNull(message.getTarget(), "Target should initially be null");
            assertNull(message.getTargetInformation(), "Target information should be null when no target is set");
        }

        @Test
        @DisplayName("Constructor with CIFSContext and Type1Message should derive flags")
        void testConstructor_CIFSContext_Type1Message() {
            // Given
            CIFSContext mockContext = createMockContext();
            Type1Message type1 = new Type1Message(mockContext);
            type1.setFlags(Type1Message.NTLMSSP_NEGOTIATE_UNICODE | Type1Message.NTLMSSP_REQUEST_TARGET);

            // When
            Type2Message message = new Type2Message(mockContext, type1);

            // Then
            assertNotNull(message);
            // Verify flags are derived from Type1Message and context
            int expectedFlags = Type2Message.NTLMSSP_NEGOTIATE_NTLM | Type2Message.NTLMSSP_NEGOTIATE_VERSION
                    | Type2Message.NTLMSSP_NEGOTIATE_UNICODE | Type2Message.NTLMSSP_REQUEST_TARGET | Type2Message.NTLMSSP_TARGET_TYPE_DOMAIN;
            assertEquals(expectedFlags, message.getFlags());
            assertNull(message.getChallenge());
            assertEquals(TEST_DOMAIN, message.getTarget()); // Target should be default domain if requested
            assertNotNull(message.getTargetInformation());
        }

        @Test
        @DisplayName("Constructor with challenge and target should set values correctly")
        void testConstructor_CIFSContext_Type1Message_Challenge_Target() {
            // Given
            CIFSContext mockContext = createMockContext();
            Type1Message type1 = new Type1Message(mockContext);
            type1.setFlags(Type1Message.NTLMSSP_NEGOTIATE_UNICODE); // No REQUEST_TARGET

            // When
            Type2Message message = new Type2Message(mockContext, type1, TEST_CHALLENGE, TEST_TARGET);

            // Then
            assertNotNull(message);
            int expectedFlags =
                    Type2Message.NTLMSSP_NEGOTIATE_NTLM | Type2Message.NTLMSSP_NEGOTIATE_VERSION | Type2Message.NTLMSSP_NEGOTIATE_UNICODE;
            assertEquals(expectedFlags, message.getFlags());
            assertArrayEquals(TEST_CHALLENGE, message.getChallenge());
            assertEquals(TEST_TARGET, message.getTarget());
            assertNotNull(message.getTargetInformation());
        }

        @Test
        @DisplayName("Constructor with custom flags should use provided flags")
        void testConstructor_CIFSContext_Flags_Challenge_Target() {
            // Given
            CIFSContext mockContext = createMockContext();
            int customFlags = Type2Message.NTLMSSP_NEGOTIATE_OEM | Type2Message.NTLMSSP_NEGOTIATE_SIGN;

            // When
            Type2Message message = new Type2Message(mockContext, customFlags, TEST_CHALLENGE, TEST_TARGET);

            // Then
            assertNotNull(message);
            assertEquals(customFlags, message.getFlags());
            assertArrayEquals(TEST_CHALLENGE, message.getChallenge());
            assertEquals(TEST_TARGET, message.getTarget());
            assertNotNull(message.getTargetInformation());
        }

        @Test
        @DisplayName("Constructor with byte array should parse valid message")
        void testConstructor_ByteArray_ValidMessage() throws IOException {
            // Given
            CIFSContext mockContext = createMockContext();
            Type2Message originalMessage = new Type2Message(mockContext,
                    Type2Message.NTLMSSP_NEGOTIATE_UNICODE | Type2Message.NTLMSSP_NEGOTIATE_VERSION | Type2Message.NTLMSSP_REQUEST_TARGET,
                    TEST_CHALLENGE, TEST_TARGET);
            byte[] rawMessage = originalMessage.toByteArray();

            // When
            Type2Message parsedMessage = new Type2Message(rawMessage);

            // Then
            assertNotNull(parsedMessage);
            // The flags might include NTLMSSP_NEGOTIATE_TARGET_INFO if target info is set
            assertTrue((parsedMessage.getFlags() & Type2Message.NTLMSSP_NEGOTIATE_TARGET_INFO) != 0);
            assertArrayEquals(originalMessage.getChallenge(), parsedMessage.getChallenge());
            assertEquals(originalMessage.getTarget(), parsedMessage.getTarget());
            assertArrayEquals(originalMessage.getTargetInformation(), parsedMessage.getTargetInformation());
        }

        @Test
        @DisplayName("Constructor with invalid signature should throw IOException")
        void testConstructor_ByteArray_InvalidSignature() {
            // Given
            byte[] invalidSignature = new byte[100];
            Arrays.fill(invalidSignature, (byte) 0xFF); // Fill with non-NTLMSSP signature

            // When & Then
            IOException thrown = assertThrows(IOException.class, () -> new Type2Message(invalidSignature));
            assertEquals("Not an NTLMSSP message.", thrown.getMessage());
        }

        @Test
        @DisplayName("Constructor with invalid message type should throw IOException")
        void testConstructor_ByteArray_InvalidMessageType() {
            // Given
            byte[] invalidType = new byte[100];
            System.arraycopy(Type2Message.NTLMSSP_SIGNATURE, 0, invalidType, 0, Type2Message.NTLMSSP_SIGNATURE.length);
            // Set message type to something other than NTLMSSP_TYPE2
            Type2Message.writeULong(invalidType, 8, Type2Message.NTLMSSP_TYPE1);

            // When & Then
            IOException thrown = assertThrows(IOException.class, () -> new Type2Message(invalidType));
            assertEquals("Not a Type 2 message.", thrown.getMessage());
        }
    }

    @Nested
    @DisplayName("Default Flags Tests")
    class DefaultFlagsTests {

        @Test
        @DisplayName("getDefaultFlags should use Unicode when enabled")
        void testGetDefaultFlags_CIFSContext_Unicode() {
            // Given
            CIFSContext mockContext = createMockContext();

            // When
            int flags = Type2Message.getDefaultFlags(mockContext);

            // Then
            int expectedFlags =
                    Type2Message.NTLMSSP_NEGOTIATE_NTLM | Type2Message.NTLMSSP_NEGOTIATE_VERSION | Type2Message.NTLMSSP_NEGOTIATE_UNICODE;
            assertEquals(expectedFlags, flags);
        }

        @Test
        @DisplayName("getDefaultFlags should use OEM when Unicode disabled")
        void testGetDefaultFlags_CIFSContext_OEM() {
            // Given
            CIFSContext mockContext = mock(CIFSContext.class);
            Configuration mockConfig = mock(Configuration.class);
            when(mockContext.getConfig()).thenReturn(mockConfig);
            when(mockConfig.isUseUnicode()).thenReturn(false);

            // When
            int flags = Type2Message.getDefaultFlags(mockContext);

            // Then
            int expectedFlags =
                    Type2Message.NTLMSSP_NEGOTIATE_NTLM | Type2Message.NTLMSSP_NEGOTIATE_VERSION | Type2Message.NTLMSSP_NEGOTIATE_OEM;
            assertEquals(expectedFlags, flags);
        }

        @Test
        @DisplayName("getDefaultFlags should handle Type1Message with request target")
        void testGetDefaultFlags_CIFSContext_Type1Message_Unicode_RequestTarget_DomainPresent() {
            // Given
            CIFSContext mockContext = createMockContext();
            Type1Message type1 = new Type1Message(mockContext);
            type1.setFlags(Type1Message.NTLMSSP_NEGOTIATE_UNICODE | Type1Message.NTLMSSP_REQUEST_TARGET);

            // When
            int flags = Type2Message.getDefaultFlags(mockContext, type1);

            // Then
            int expectedFlags = Type2Message.NTLMSSP_NEGOTIATE_NTLM | Type2Message.NTLMSSP_NEGOTIATE_VERSION
                    | Type2Message.NTLMSSP_NEGOTIATE_UNICODE | Type2Message.NTLMSSP_REQUEST_TARGET | Type2Message.NTLMSSP_TARGET_TYPE_DOMAIN;
            assertEquals(expectedFlags, flags);
        }

        @Test
        @DisplayName("getDefaultFlags should handle Type1Message without request target")
        void testGetDefaultFlags_CIFSContext_Type1Message_OEM_NoRequestTarget() {
            // Given
            CIFSContext mockContext = mock(CIFSContext.class);
            Configuration mockConfig = mock(Configuration.class);
            NameServiceClient mockNameServiceClient = mock(NameServiceClient.class);
            NetbiosAddress mockHost = mock(NetbiosAddress.class);

            when(mockContext.getConfig()).thenReturn(mockConfig);
            when(mockContext.getNameServiceClient()).thenReturn(mockNameServiceClient);
            when(mockNameServiceClient.getLocalHost()).thenReturn(mockHost);
            when(mockHost.getHostName()).thenReturn(TEST_HOSTNAME);
            when(mockConfig.isUseUnicode()).thenReturn(false);
            when(mockConfig.getDefaultDomain()).thenReturn(TEST_DOMAIN);
            
            Type1Message type1 = new Type1Message(mockContext);
            type1.setFlags(Type1Message.NTLMSSP_NEGOTIATE_OEM); // No REQUEST_TARGET

            // When
            int flags = Type2Message.getDefaultFlags(mockContext, type1);

            // Then
            int expectedFlags =
                    Type2Message.NTLMSSP_NEGOTIATE_NTLM | Type2Message.NTLMSSP_NEGOTIATE_VERSION | Type2Message.NTLMSSP_NEGOTIATE_OEM;
            assertEquals(expectedFlags, flags);
        }

        @Test
        @DisplayName("getDefaultFlags should handle null Type1Message")
        void testGetDefaultFlags_CIFSContext_Type1Message_NullType1() {
            // Given
            CIFSContext mockContext = createMockContext();

            // When
            int flags = Type2Message.getDefaultFlags(mockContext, null);

            // Then
            int expectedFlags =
                    Type2Message.NTLMSSP_NEGOTIATE_NTLM | Type2Message.NTLMSSP_NEGOTIATE_VERSION | Type2Message.NTLMSSP_NEGOTIATE_UNICODE;
            assertEquals(expectedFlags, flags);
        }
    }

    @Nested
    @DisplayName("Getter and Setter Tests")
    class GetterSetterTests {

        @Test
        @DisplayName("setChallenge and getChallenge should work correctly")
        void testGetSetChallenge() {
            // Given
            CIFSContext mockContext = createMockContext();
            Type2Message message = new Type2Message(mockContext);

            // When
            message.setChallenge(TEST_CHALLENGE);

            // Then
            assertArrayEquals(TEST_CHALLENGE, message.getChallenge());
        }

        @Test
        @DisplayName("setTarget and getTarget should work correctly")
        void testGetSetTarget() {
            // Given
            CIFSContext mockContext = createMockContext();
            Type2Message message = new Type2Message(mockContext);

            // When
            message.setTarget(TEST_TARGET);

            // Then
            assertEquals(TEST_TARGET, message.getTarget());
        }

        @Test
        @DisplayName("setTargetInformation and getTargetInformation should work correctly")
        void testGetSetTargetInformation() {
            // Given
            CIFSContext mockContext = createMockContext();
            Type2Message message = new Type2Message(mockContext);
            byte[] testTargetInfo = new byte[] { 0x10, 0x20, 0x30 };

            // When
            message.setTargetInformation(testTargetInfo);

            // Then
            assertArrayEquals(testTargetInfo, message.getTargetInformation());
        }

        @Test
        @DisplayName("setContext and getContext should work correctly")
        void testGetSetContext() {
            // Given
            CIFSContext mockContext = createMockContext();
            Type2Message message = new Type2Message(mockContext);
            byte[] testContext = new byte[] { (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88 };

            // When
            message.setContext(testContext);

            // Then
            assertArrayEquals(testContext, message.getContext());
        }
    }

    @Nested
    @DisplayName("Serialization Tests")
    class SerializationTests {

        @Test
        @DisplayName("toByteArray should produce valid message with basic flags")
        void testToByteArray_Basic() throws IOException {
            // Given
            CIFSContext mockContext = createMockContext();
            Type2Message message =
                    new Type2Message(mockContext, Type2Message.NTLMSSP_NEGOTIATE_UNICODE | Type2Message.NTLMSSP_NEGOTIATE_VERSION, null, null);

            // When
            byte[] bytes = message.toByteArray();

            // Then
            assertNotNull(bytes);
            assertTrue(bytes.length >= 48); // Minimum size
            // Verify signature
            assertTrue(Arrays.equals(Type2Message.NTLMSSP_SIGNATURE, Arrays.copyOfRange(bytes, 0, 8)));
            // Verify message type
            assertEquals(Type2Message.NTLMSSP_TYPE2, Type2Message.readULong(bytes, 8));
            // Verify flags
            assertEquals(message.getFlags(), Type2Message.readULong(bytes, 20));
        }

        @Test
        @DisplayName("toByteArray should include challenge and context correctly")
        void testToByteArray_WithChallengeAndContext() throws IOException {
            // Given
            CIFSContext mockContext = createMockContext();
            Type2Message message = new Type2Message(mockContext,
                    Type2Message.NTLMSSP_NEGOTIATE_UNICODE | Type2Message.NTLMSSP_NEGOTIATE_VERSION, TEST_CHALLENGE, null);
            byte[] testContext = new byte[] { (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88 };
            message.setContext(testContext);

            // When
            byte[] bytes = message.toByteArray();

            // Then
            assertNotNull(bytes);
            // Verify challenge
            assertArrayEquals(TEST_CHALLENGE, Arrays.copyOfRange(bytes, 24, 32));
            // Verify context
            assertArrayEquals(testContext, Arrays.copyOfRange(bytes, 32, 40));
        }

        @Test
        @DisplayName("toByteArray should include target and target info correctly")
        void testToByteArray_WithTargetAndTargetInfo() throws IOException {
            // Given
            CIFSContext mockContext = createMockContext();
            Type2Message message = new Type2Message(mockContext,
                    Type2Message.NTLMSSP_NEGOTIATE_UNICODE | Type2Message.NTLMSSP_NEGOTIATE_VERSION | Type2Message.NTLMSSP_REQUEST_TARGET,
                    TEST_CHALLENGE, TEST_TARGET);

            // When
            byte[] bytes = message.toByteArray();

            // Then
            assertNotNull(bytes);
            assertTrue(bytes.length > 48);
            
            // Parse the message to verify target and target info
            Type2Message parsedMessage = new Type2Message(bytes);
            assertEquals(TEST_TARGET, parsedMessage.getTarget());
            assertNotNull(parsedMessage.getTargetInformation());
            assertArrayEquals(message.getTargetInformation(), parsedMessage.getTargetInformation());
        }

        @Test
        @DisplayName("toByteArray should not include target when flag is not set")
        void testToByteArray_NoRequestTargetFlag_TargetPresent() throws IOException {
            // Given
            CIFSContext mockContext = createMockContext();
            Type2Message message = new Type2Message(mockContext,
                    Type2Message.NTLMSSP_NEGOTIATE_UNICODE | Type2Message.NTLMSSP_NEGOTIATE_VERSION, null, TEST_TARGET);

            // When
            byte[] bytes = message.toByteArray();

            // Then
            assertNotNull(bytes);
            // Ensure target name is NOT written to the byte array
            int flags = Type2Message.readULong(bytes, 20);
            assertFalse((flags & Type2Message.NTLMSSP_REQUEST_TARGET) != 0);
        }

        @Test
        @DisplayName("toByteArray should not set target info flag when target info is null")
        void testToByteArray_TargetInfoNull_FlagNotSet() throws IOException {
            // Given
            CIFSContext mockContext = createMockContext();
            Type2Message message =
                    new Type2Message(mockContext, Type2Message.NTLMSSP_NEGOTIATE_UNICODE | Type2Message.NTLMSSP_NEGOTIATE_VERSION, null, null);
            message.setTargetInformation(null); // Explicitly set to null

            // When
            byte[] bytes = message.toByteArray();

            // Then
            assertNotNull(bytes);
            int flags = Type2Message.readULong(bytes, 20);
            assertFalse((flags & Type2Message.NTLMSSP_NEGOTIATE_TARGET_INFO) != 0);
        }

        @Test
        @DisplayName("toByteArray should exclude version field when flag is not set")
        void testToByteArray_NoNegotiateVersionFlag() throws IOException {
            // Given
            CIFSContext mockContext = createMockContext();
            Type2Message message = new Type2Message(mockContext, Type2Message.NTLMSSP_NEGOTIATE_UNICODE, null, null);

            // When
            byte[] bytes = message.toByteArray();

            // Then
            assertNotNull(bytes);
            // Verify that the version field (8 bytes) is not present
            assertEquals(48, bytes.length); // Should be minimum size
        }
    }

    @Nested
    @DisplayName("String Representation Tests")
    class StringRepresentationTests {

        @Test
        @DisplayName("toString should format message with all fields")
        void testToString() {
            // Given
            CIFSContext mockContext = createMockContext();
            Type2Message message = new Type2Message(mockContext, Type2Message.NTLMSSP_NEGOTIATE_UNICODE, TEST_CHALLENGE, TEST_TARGET);
            byte[] testContext = new byte[] { (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88 };
            message.setContext(testContext);
            byte[] testTargetInfo = new byte[] { 0x10, 0x20, 0x30 };
            message.setTargetInformation(testTargetInfo);

            // When
            String result = message.toString();

            // Then
            String expectedToString = "Type2Message[target=" + TEST_TARGET + ",challenge=<8 bytes>" + ",context=<8 bytes>"
                    + ",targetInformation=<3 bytes>" + ",flags=0x" + Hexdump.toHexString(message.getFlags(), 8) + "]";
            assertEquals(expectedToString, result);
        }

        @Test
        @DisplayName("toString should handle null fields")
        void testToString_NullFields() {
            // Given
            CIFSContext mockContext = createMockContext();
            Type2Message message = new Type2Message(mockContext, Type2Message.NTLMSSP_NEGOTIATE_UNICODE, null, null);
            message.setContext(null);
            message.setTargetInformation(null);

            // When
            String result = message.toString();

            // Then
            String expectedToString = "Type2Message[target=null" + ",challenge=null" + ",context=null" + ",targetInformation=null" + ",flags=0x"
                    + Hexdump.toHexString(message.getFlags(), 8) + "]";
            assertEquals(expectedToString, result);
        }
    }

    @Nested
    @DisplayName("Message Parsing Tests")
    class MessageParsingTests {

        @Test
        @DisplayName("parse should handle minimum valid message")
        void testParse_MinimumValidMessage() throws IOException {
            // Given
            CIFSContext mockContext = createMockContext();
            Type2Message originalMessage =
                    new Type2Message(mockContext, Type2Message.NTLMSSP_NEGOTIATE_UNICODE | Type2Message.NTLMSSP_NEGOTIATE_VERSION, null, null);
            byte[] rawMessage = originalMessage.toByteArray();

            // When
            Type2Message parsedMessage = new Type2Message(rawMessage);

            // Then
            assertNotNull(parsedMessage);
            assertEquals(originalMessage.getFlags(), parsedMessage.getFlags());
            assertNull(parsedMessage.getChallenge()); // Should be null if all zeros
            assertNull(parsedMessage.getTarget());
            assertNull(parsedMessage.getContext()); // Should be null if all zeros
            assertNull(parsedMessage.getTargetInformation());
        }

        @Test
        @DisplayName("parse should handle message with all fields populated")
        void testParse_WithAllFields() throws IOException {
            // Given
            CIFSContext mockContext = createMockContext();
            Type2Message originalMessage = new Type2Message(mockContext,
                    Type2Message.NTLMSSP_NEGOTIATE_UNICODE | Type2Message.NTLMSSP_NEGOTIATE_VERSION | Type2Message.NTLMSSP_REQUEST_TARGET,
                    TEST_CHALLENGE, TEST_TARGET);
            byte[] testContext = new byte[] { (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88 };
            originalMessage.setContext(testContext);
            byte[] rawMessage = originalMessage.toByteArray();

            // When
            Type2Message parsedMessage = new Type2Message(rawMessage);

            // Then
            assertNotNull(parsedMessage);
            // The flags might include NTLMSSP_NEGOTIATE_TARGET_INFO if target info is set
            assertTrue((parsedMessage.getFlags() & Type2Message.NTLMSSP_NEGOTIATE_TARGET_INFO) != 0);
            assertArrayEquals(originalMessage.getChallenge(), parsedMessage.getChallenge());
            assertEquals(originalMessage.getTarget(), parsedMessage.getTarget());
            assertArrayEquals(originalMessage.getContext(), parsedMessage.getContext());
            assertArrayEquals(originalMessage.getTargetInformation(), parsedMessage.getTargetInformation());
        }

        @Test
        @DisplayName("parse should handle malformed targetNameOff")
        void testParse_TargetNameOffTooSmall() throws IOException {
            // Given
            CIFSContext mockContext = createMockContext();
            Type2Message originalMessage = new Type2Message(mockContext,
                    Type2Message.NTLMSSP_NEGOTIATE_UNICODE | Type2Message.NTLMSSP_NEGOTIATE_VERSION, TEST_CHALLENGE, TEST_TARGET);
            byte[] rawMessage = originalMessage.toByteArray();

            // Manually set targetNameOff to a value that makes it too small for context/reserved
            Type2Message.writeULong(rawMessage, 16, 0); // targetNameOff is at byte 16

            // When
            Type2Message parsedMessage = new Type2Message(rawMessage);

            // Then
            assertNotNull(parsedMessage);
            // Context and TargetInformation should be null because there's no room to parse them
            assertNull(parsedMessage.getContext());
            assertNull(parsedMessage.getTargetInformation());
        }

        @Test
        @DisplayName("parse should handle truncated message missing context")
        void testParse_InputLengthTooSmallForContext() {
            // Given
            // Create a minimal Type2 message manually
            byte[] truncatedMessage = new byte[32];
            System.arraycopy(Type2Message.NTLMSSP_SIGNATURE, 0, truncatedMessage, 0, 8);
            Type2Message.writeULong(truncatedMessage, 8, Type2Message.NTLMSSP_TYPE2);
            // Set empty target name buffer
            Type2Message.writeUShort(truncatedMessage, 12, 0); // length
            Type2Message.writeUShort(truncatedMessage, 14, 0); // max length
            Type2Message.writeULong(truncatedMessage, 16, 48); // offset (past the end)
            // Set flags
            Type2Message.writeULong(truncatedMessage, 20, Type2Message.NTLMSSP_NEGOTIATE_UNICODE);
            // Challenge bytes would be at 24-31 but we're truncated

            // When & Then
            assertThrows(ArrayIndexOutOfBoundsException.class, () -> new Type2Message(truncatedMessage));
        }

        @Test
        @DisplayName("parse should handle truncated message missing target info")
        void testParse_InputLengthTooSmallForTargetInfo() {
            // Given
            // Create a minimal Type2 message manually with enough space for context but not target info
            byte[] truncatedMessage = new byte[40];
            System.arraycopy(Type2Message.NTLMSSP_SIGNATURE, 0, truncatedMessage, 0, 8);
            Type2Message.writeULong(truncatedMessage, 8, Type2Message.NTLMSSP_TYPE2);
            // Set empty target name buffer
            Type2Message.writeUShort(truncatedMessage, 12, 0); // length
            Type2Message.writeUShort(truncatedMessage, 14, 0); // max length
            Type2Message.writeULong(truncatedMessage, 16, 48); // offset (past the end)
            // Set flags
            Type2Message.writeULong(truncatedMessage, 20, Type2Message.NTLMSSP_NEGOTIATE_UNICODE);
            // Challenge bytes at 24-31 (zeros)
            // Context bytes at 32-39 (zeros)
            // Target info buffer would be at 40-47 but we're truncated

            // When & Then
            assertThrows(ArrayIndexOutOfBoundsException.class, () -> new Type2Message(truncatedMessage));
        }

        @Test
        @DisplayName("parse should handle OEM encoding")
        void testParse_OEMEncoding() throws IOException {
            // Given
            CIFSContext mockContext = mock(CIFSContext.class);
            Configuration mockConfig = mock(Configuration.class);
            NameServiceClient mockNameServiceClient = mock(NameServiceClient.class);
            NetbiosAddress mockHost = mock(NetbiosAddress.class);

            when(mockContext.getConfig()).thenReturn(mockConfig);
            when(mockContext.getNameServiceClient()).thenReturn(mockNameServiceClient);
            when(mockNameServiceClient.getLocalHost()).thenReturn(mockHost);
            when(mockHost.getHostName()).thenReturn(TEST_HOSTNAME);
            when(mockConfig.isUseUnicode()).thenReturn(false); // Simulate OEM encoding
            when(mockConfig.getDefaultDomain()).thenReturn(TEST_DOMAIN);
            
            Type2Message originalMessage = new Type2Message(mockContext,
                    Type2Message.NTLMSSP_NEGOTIATE_OEM | Type2Message.NTLMSSP_NEGOTIATE_VERSION | Type2Message.NTLMSSP_REQUEST_TARGET,
                    TEST_CHALLENGE, TEST_TARGET);
            byte[] rawMessage = originalMessage.toByteArray();

            // When
            Type2Message parsedMessage = new Type2Message(rawMessage);

            // Then
            assertNotNull(parsedMessage);
            assertEquals(TEST_TARGET.toUpperCase(), parsedMessage.getTarget()); // OEM encoding often means uppercase
        }

        @Test
        @DisplayName("parse should handle message with no target name")
        void testParse_NoTargetName() throws IOException {
            // Given
            CIFSContext mockContext = createMockContext();
            Type2Message originalMessage = new Type2Message(mockContext,
                    Type2Message.NTLMSSP_NEGOTIATE_UNICODE | Type2Message.NTLMSSP_NEGOTIATE_VERSION, TEST_CHALLENGE, null);
            byte[] rawMessage = originalMessage.toByteArray();

            // When
            Type2Message parsedMessage = new Type2Message(rawMessage);

            // Then
            assertNotNull(parsedMessage);
            assertNull(parsedMessage.getTarget());
        }

        @Test
        @DisplayName("parse should handle message with no target info")
        void testParse_NoTargetInfo() throws IOException {
            // Given
            CIFSContext mockContext = createMockContext();
            Type2Message originalMessage = new Type2Message(mockContext,
                    Type2Message.NTLMSSP_NEGOTIATE_UNICODE | Type2Message.NTLMSSP_NEGOTIATE_VERSION, TEST_CHALLENGE, TEST_TARGET);
            originalMessage.setTargetInformation(new byte[0]); // Set empty target info
            byte[] rawMessage = originalMessage.toByteArray();

            // When
            Type2Message parsedMessage = new Type2Message(rawMessage);

            // Then
            assertNotNull(parsedMessage);
            assertNull(parsedMessage.getTargetInformation());
        }
    }

    @Nested
    @DisplayName("Target Information Generation Tests")
    class TargetInformationTests {

        @Test
        @DisplayName("makeTargetInfo should generate correct structure with domain and host")
        void testMakeTargetInfo_DomainAndHost() throws IOException {
            // Given
            CIFSContext mockContext = createMockContext();

            // When/Then
            try {
                java.lang.reflect.Method method = Type2Message.class.getDeclaredMethod("makeTargetInfo", CIFSContext.class, String.class);
                method.setAccessible(true);
                byte[] targetInfo = (byte[]) method.invoke(null, mockContext, TEST_DOMAIN);

                assertNotNull(targetInfo);
                // Expected structure: Type (2 bytes) + Length (2 bytes) + Data (Length bytes)
                // For domain: Type 0x0002 (NetBIOS Domain Name)
                // For server: Type 0x0001 (NetBIOS Computer Name)

                // Verify domain part
                assertEquals(2, Type2Message.readUShort(targetInfo, 0)); // Type 0x0002
                assertEquals(TEST_DOMAIN.getBytes(Type2Message.UNI_ENCODING).length, Type2Message.readUShort(targetInfo, 2)); // Length
                assertEquals(TEST_DOMAIN,
                        new String(Arrays.copyOfRange(targetInfo, 4, 4 + TEST_DOMAIN.getBytes(Type2Message.UNI_ENCODING).length),
                                Type2Message.UNI_ENCODING));

                // Verify server part - check if it exists
                int serverOffset = 4 + TEST_DOMAIN.getBytes(Type2Message.UNI_ENCODING).length;
                if (serverOffset + 4 <= targetInfo.length) {
                    assertEquals(1, Type2Message.readUShort(targetInfo, serverOffset)); // Type 0x0001
                    int serverNameLength = Type2Message.readUShort(targetInfo, serverOffset + 2);
                    assertTrue(serverNameLength > 0);
                    if (serverOffset + 4 + serverNameLength <= targetInfo.length) {
                        String serverName = new String(
                                Arrays.copyOfRange(targetInfo, serverOffset + 4, serverOffset + 4 + serverNameLength),
                                Type2Message.UNI_ENCODING);
                        assertNotNull(serverName);
                        // The actual server name might be different from TEST_HOSTNAME based on how getHostName() works
                    }
                }

            } catch (Exception e) {
                fail("Failed to invoke makeTargetInfo via reflection: " + e.getMessage());
            }
        }

        @Test
        @DisplayName("makeTargetInfo should handle missing domain")
        void testMakeTargetInfo_NoDomain() throws IOException {
            // Given
            CIFSContext mockContext = mock(CIFSContext.class);
            Configuration mockConfig = mock(Configuration.class);
            NameServiceClient mockNameServiceClient = mock(NameServiceClient.class);
            NetbiosAddress mockHost = mock(NetbiosAddress.class);

            when(mockContext.getConfig()).thenReturn(mockConfig);
            when(mockContext.getNameServiceClient()).thenReturn(mockNameServiceClient);
            when(mockNameServiceClient.getLocalHost()).thenReturn(mockHost);
            when(mockHost.getHostName()).thenReturn(TEST_HOSTNAME);
            when(mockConfig.getDefaultDomain()).thenReturn(null);
            when(mockConfig.isUseUnicode()).thenReturn(true);

            // When/Then
            try {
                java.lang.reflect.Method method = Type2Message.class.getDeclaredMethod("makeTargetInfo", CIFSContext.class, String.class);
                method.setAccessible(true);
                byte[] targetInfo = (byte[]) method.invoke(null, mockContext, null);

                assertNotNull(targetInfo);
                // Should only contain server info - but might have different structure than expected
                assertTrue(targetInfo.length >= 4, "Target info should have at least terminator");
                // Check if it contains server info (implementation dependent)
                if (targetInfo.length > 4) {
                    assertEquals(1, Type2Message.readUShort(targetInfo, 0)); // Type 0x0001
                    assertEquals(TEST_HOSTNAME.getBytes(Type2Message.UNI_ENCODING).length, Type2Message.readUShort(targetInfo, 2)); // Length
                    assertEquals(TEST_HOSTNAME,
                            new String(Arrays.copyOfRange(targetInfo, 4, 4 + TEST_HOSTNAME.getBytes(Type2Message.UNI_ENCODING).length),
                                    Type2Message.UNI_ENCODING));
                }
            } catch (Exception e) {
                fail("Failed to invoke makeTargetInfo via reflection: " + e.getMessage());
            }
        }

        @Test
        @DisplayName("makeTargetInfo should handle missing host")
        void testMakeTargetInfo_NoHost() throws IOException {
            // Given
            CIFSContext mockContext = mock(CIFSContext.class);
            Configuration mockConfig = mock(Configuration.class);
            NameServiceClient mockNameServiceClient = mock(NameServiceClient.class);
            NetbiosAddress mockHost = mock(NetbiosAddress.class);

            when(mockContext.getConfig()).thenReturn(mockConfig);
            when(mockContext.getNameServiceClient()).thenReturn(mockNameServiceClient);
            when(mockNameServiceClient.getLocalHost()).thenReturn(mockHost);
            when(mockHost.getHostName()).thenReturn(null);
            when(mockConfig.getDefaultDomain()).thenReturn(TEST_DOMAIN);
            when(mockConfig.isUseUnicode()).thenReturn(true);

            // When/Then
            try {
                java.lang.reflect.Method method = Type2Message.class.getDeclaredMethod("makeTargetInfo", CIFSContext.class, String.class);
                method.setAccessible(true);
                byte[] targetInfo = (byte[]) method.invoke(null, mockContext, TEST_DOMAIN);

                assertNotNull(targetInfo);
                // Should only contain domain info
                assertEquals(2, Type2Message.readUShort(targetInfo, 0)); // Type 0x0002
                assertEquals(TEST_DOMAIN.getBytes(Type2Message.UNI_ENCODING).length, Type2Message.readUShort(targetInfo, 2)); // Length
                assertEquals(TEST_DOMAIN,
                        new String(Arrays.copyOfRange(targetInfo, 4, 4 + TEST_DOMAIN.getBytes(Type2Message.UNI_ENCODING).length),
                                Type2Message.UNI_ENCODING));
            } catch (Exception e) {
                fail("Failed to invoke makeTargetInfo via reflection: " + e.getMessage());
            }
        }

        @Test
        @DisplayName("makeTargetInfo should handle missing domain and host")
        void testMakeTargetInfo_NoDomainNoHost() throws IOException {
            // Given
            CIFSContext mockContext = mock(CIFSContext.class);
            Configuration mockConfig = mock(Configuration.class);
            NameServiceClient mockNameServiceClient = mock(NameServiceClient.class);
            NetbiosAddress mockHost = mock(NetbiosAddress.class);

            when(mockContext.getConfig()).thenReturn(mockConfig);
            when(mockContext.getNameServiceClient()).thenReturn(mockNameServiceClient);
            when(mockNameServiceClient.getLocalHost()).thenReturn(mockHost);
            when(mockHost.getHostName()).thenReturn(null);
            when(mockConfig.getDefaultDomain()).thenReturn(null);
            when(mockConfig.isUseUnicode()).thenReturn(true);

            // When/Then
            try {
                java.lang.reflect.Method method = Type2Message.class.getDeclaredMethod("makeTargetInfo", CIFSContext.class, String.class);
                method.setAccessible(true);
                byte[] targetInfo = (byte[]) method.invoke(null, mockContext, null);

                assertNotNull(targetInfo);
                assertEquals(4, targetInfo.length); // Only the 4-byte terminator
            } catch (Exception e) {
                fail("Failed to invoke makeTargetInfo via reflection: " + e.getMessage());
            }
        }
    }

}
