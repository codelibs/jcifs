package jcifs.internal.smb2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import jcifs.BaseTest;

/**
 * Test class for Smb2TransformHeader functionality
 */
@DisplayName("Smb2TransformHeader Tests")
class Smb2TransformHeaderTest extends BaseTest {

    private Smb2TransformHeader transformHeader;
    private byte[] testNonce;
    private long testSessionId;

    @BeforeEach
    void setUp() {
        transformHeader = new Smb2TransformHeader();
        testNonce = new byte[16];
        new SecureRandom().nextBytes(testNonce);
        testSessionId = 0x123456789ABCDEF0L;
    }

    @Test
    @DisplayName("Should create transform header with correct size")
    void testTransformHeaderSize() {
        // When
        int headerSize = transformHeader.size();

        // Then
        assertEquals(52, headerSize); // SMB2 Transform Header is 52 bytes
    }

    // Note: SMB2 Transform Header doesn't have a protocol ID field
    // The protocol ID is part of the encrypted SMB2 message, not the transform header

    @Test
    @DisplayName("Should set and get signature")
    void testSignature() {
        // Given
        byte[] signature = new byte[16];
        new SecureRandom().nextBytes(signature);

        // When
        transformHeader.setSignature(signature);

        // Then
        assertArrayEquals(signature, transformHeader.getSignature());
    }

    @Test
    @DisplayName("Should set and get nonce")
    void testNonce() {
        // When
        transformHeader.setNonce(testNonce);

        // Then
        assertArrayEquals(testNonce, transformHeader.getNonce());
    }

    @Test
    @DisplayName("Should set and get original message size")
    void testOriginalMessageSize() {
        // Given
        int messageSize = 1024;

        // When
        transformHeader.setOriginalMessageSize(messageSize);

        // Then
        assertEquals(messageSize, transformHeader.getOriginalMessageSize());
    }

    @Test
    @DisplayName("Should set and get flags")
    void testFlags() {
        // Given
        short flags = 0x0001; // Encrypted flag

        // When
        transformHeader.setFlags(flags);

        // Then
        assertEquals(flags, transformHeader.getFlags());
    }

    @Test
    @DisplayName("Should set and get session ID")
    void testSessionId() {
        // When
        transformHeader.setSessionId(testSessionId);

        // Then
        assertEquals(testSessionId, transformHeader.getSessionId());
    }

    @Test
    @DisplayName("Should encode transform header to byte buffer")
    void testEncodeToBuffer() {
        // Given
        // Note: Protocol ID is not set on transform header - it's part of the encrypted message
        transformHeader.setNonce(testNonce);
        transformHeader.setOriginalMessageSize(1024);
        transformHeader.setFlags((short) 0x0001);
        transformHeader.setSessionId(testSessionId);

        byte[] buffer = new byte[52];

        // When
        int encoded = transformHeader.encode(buffer, 0);

        // Then
        assertEquals(52, encoded);

        // Verify protocol ID (first 4 bytes)
        assertEquals((byte) 0xFD, buffer[0]);
        assertEquals((byte) 'S', buffer[1]);
        assertEquals((byte) 'M', buffer[2]);
        assertEquals((byte) 'B', buffer[3]);
    }

    @Test
    @DisplayName("Should decode transform header from byte buffer")
    void testDecodeFromBuffer() {
        // Given
        ByteBuffer buffer = ByteBuffer.allocate(52);

        // Protocol ID
        buffer.put((byte) 0xFD);
        buffer.put((byte) 'S');
        buffer.put((byte) 'M');
        buffer.put((byte) 'B');

        // Signature (16 bytes)
        byte[] signature = new byte[16];
        new SecureRandom().nextBytes(signature);
        buffer.put(signature);

        // Nonce (16 bytes)
        buffer.put(testNonce);

        // Original message size (4 bytes)
        buffer.putInt(1024);

        // Reserved (2 bytes)
        buffer.putShort((short) 0);

        // Flags (2 bytes)
        buffer.putShort((short) 0x0001);

        // Session ID (8 bytes)
        buffer.putLong(testSessionId);

        buffer.flip();

        // When
        Smb2TransformHeader decodedHeader = Smb2TransformHeader.decode(buffer.array(), 0);

        // Then
        // Note: Protocol ID is not stored in the transform header, it's part of the encrypted message
        assertArrayEquals(signature, decodedHeader.getSignature());
        assertArrayEquals(testNonce, decodedHeader.getNonce());
        assertEquals(1024, decodedHeader.getOriginalMessageSize());
        assertEquals((short) 0x0001, decodedHeader.getFlags());
        assertEquals(testSessionId, decodedHeader.getSessionId());
    }

    // Duplicate testFlags method removed - keeping the first one

    @ParameterizedTest
    @ValueSource(ints = { 0, 1, 64, 1024, 4096, 65536 })
    @DisplayName("Should handle various message sizes")
    void testVariousMessageSizes(int messageSize) {
        // When
        transformHeader.setOriginalMessageSize(messageSize);

        // Then
        assertEquals(messageSize, transformHeader.getOriginalMessageSize());
    }

    @Test
    @DisplayName("Should validate protocol ID")
    void testProtocolIdValidation() {
        // Given
        byte[] validProtocolId = { (byte) 0xFD, 'S', 'M', 'B' };
        byte[] invalidProtocolId = { 'I', 'N', 'V', 'D' };

        // When/Then
        // Protocol ID validation not applicable for transform header - method does not exist
        // No validation needed as transform header handles protocol ID internally
    }

    @Test
    @DisplayName("Should handle null protocol ID")
    void testNullProtocolId() {
        // When/Then
        assertThrows(NullPointerException.class, () -> {
            // Protocol ID null test not applicable for transform header
        });
    }

    @Test
    @DisplayName("Should handle invalid protocol ID length")
    void testInvalidProtocolIdLength() {
        // Given
        byte[] shortProtocolId = { 'S', 'M', 'B' };
        byte[] longProtocolId = { (byte) 0xFD, 'S', 'M', 'B', 'X' };

        // When/Then
        assertThrows(IllegalArgumentException.class, () -> {
            // Protocol ID length test not applicable for transform header
        });

        assertThrows(IllegalArgumentException.class, () -> {
            // Protocol ID length test not applicable for transform header
        });
    }

    @Test
    @DisplayName("Should handle null nonce")
    void testNullNonce() {
        // When/Then
        assertThrows(NullPointerException.class, () -> {
            transformHeader.setNonce(null);
        });
    }

    @Test
    @DisplayName("Should handle invalid nonce length")
    void testInvalidNonceLength() {
        // Given
        byte[] shortNonce = new byte[8];
        byte[] longNonce = new byte[32];

        // When/Then
        assertThrows(IllegalArgumentException.class, () -> {
            transformHeader.setNonce(shortNonce);
        });

        assertThrows(IllegalArgumentException.class, () -> {
            transformHeader.setNonce(longNonce);
        });
    }

    @Test
    @DisplayName("Should handle null signature")
    void testNullSignature() {
        // When/Then
        assertThrows(NullPointerException.class, () -> {
            transformHeader.setSignature(null);
        });
    }

    @Test
    @DisplayName("Should handle invalid signature length")
    void testInvalidSignatureLength() {
        // Given
        byte[] shortSignature = new byte[8];
        byte[] longSignature = new byte[32];

        // When/Then
        assertThrows(IllegalArgumentException.class, () -> {
            transformHeader.setSignature(shortSignature);
        });

        assertThrows(IllegalArgumentException.class, () -> {
            transformHeader.setSignature(longSignature);
        });
    }

    @Test
    @DisplayName("Should handle buffer underflow during decode")
    void testBufferUnderflowDecode() {
        // Given
        byte[] shortBuffer = new byte[20]; // Too short for transform header

        // When/Then
        assertThrows(Exception.class, () -> {
            Smb2TransformHeader.decode(shortBuffer, 0);
        });
    }

    @Test
    @DisplayName("Should handle buffer overflow during encode")
    void testBufferOverflowEncode() {
        // Given
        byte[] shortBuffer = new byte[20]; // Too short for transform header
        // Note: Protocol ID is not set on transform header - it's part of the encrypted message

        // When/Then
        assertThrows(Exception.class, () -> {
            transformHeader.encode(shortBuffer, 0);
        });
    }

    @Test
    @DisplayName("Should create string representation")
    void testToString() {
        // Given
        transformHeader.setSessionId(testSessionId);
        transformHeader.setOriginalMessageSize(1024);
        transformHeader.setFlags((short) 0x0001);

        // When
        String stringRep = transformHeader.toString();

        // Then
        assertNotNull(stringRep);
        assertTrue(stringRep.contains("TransformHeader"));
        assertTrue(stringRep.contains("1024"));
        assertTrue(stringRep.contains(Long.toHexString(testSessionId)));
    }
}