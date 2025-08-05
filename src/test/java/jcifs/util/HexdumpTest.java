package jcifs.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import jcifs.BaseTest;

/**
 * Test class for Hexdump utility functionality
 */
@DisplayName("Hexdump Utility Tests")
class HexdumpTest extends BaseTest {

    @Test
    @DisplayName("Should convert byte array to hex string")
    void testToHexString() {
        // Given
        byte[] data = { 0x00, 0x0F, (byte) 0xFF, 0x7F, (byte) 0x80 };

        // When
        String result = Hexdump.toHexString(data);

        // Then
        assertNotNull(result);
        assertEquals("000FFF7F80", result);
    }

    @Test
    @DisplayName("Should handle empty byte array")
    void testToHexStringEmpty() {
        // Given
        byte[] data = {};

        // When
        String result = Hexdump.toHexString(data);

        // Then
        assertNotNull(result);
        assertEquals("", result);
    }

    @Test
    @DisplayName("Should handle null byte array")
    void testToHexStringNull() {
        // When/Then
        assertThrows(NullPointerException.class, () -> {
            Hexdump.toHexString(null);
        });
    }

    @Test
    @DisplayName("Should convert byte array to hex string with offset and length")
    void testHexdumpWithOffset() {
        // Given
        byte[] data = createTestData(32);

        // When
        String result = Hexdump.toHexString(data, 0, data.length);

        // Then
        assertNotNull(result);
        assertFalse(result.isEmpty());
        // Should contain hex representation of first bytes
        assertTrue(result.startsWith("00010203"));
        assertEquals(64, result.length()); // 32 bytes * 2 chars per byte
    }

    @ParameterizedTest
    @ValueSource(ints = { 1, 16, 32, 64, 128, 256 })
    @DisplayName("Should handle various data sizes")
    void testVariousDataSizes(int size) {
        // Given
        byte[] data = createTestData(size);

        // When
        String result = Hexdump.toHexString(data);

        // Then
        assertNotNull(result);
        assertFalse(result.isEmpty());
        assertEquals(size * 2, result.length()); // Each byte becomes 2 hex chars
    }

    @Test
    @DisplayName("Should format with specific offset and length")
    void testHexdumpWithOffsetAndLength() {
        // Given
        byte[] data = createTestData(64);
        int offset = 16;
        int length = 32;

        // When
        String result = Hexdump.toHexString(data, offset, length);

        // Then
        assertNotNull(result);
        assertFalse(result.isEmpty());
        // Check starts with byte at offset 16 (0x10)
        assertTrue(result.startsWith("10111213"));
        assertEquals(64, result.length()); // 32 bytes * 2 chars per byte
    }

    @Test
    @DisplayName("Should handle invalid offset and length parameters")
    void testInvalidParameters() {
        // Given
        byte[] data = createTestData(32);

        // When/Then
        assertThrows(IndexOutOfBoundsException.class, () -> {
            Hexdump.toHexString(data, -1, 16);
        });

        assertThrows(IndexOutOfBoundsException.class, () -> {
            Hexdump.toHexString(data, 0, data.length + 1);
        });

        assertThrows(IndexOutOfBoundsException.class, () -> {
            Hexdump.toHexString(data, 16, 32); // offset + length > data.length
        });
    }

    @Test
    @DisplayName("Should convert integer to hex string with padding")
    void testIntToHexString() {
        // Test various integer values
        assertEquals("00000000", Hexdump.toHexString(0, 8));
        assertEquals("000000FF", Hexdump.toHexString(255, 8));
        assertEquals("00001000", Hexdump.toHexString(4096, 8));
        assertEquals("FFFFFFFF", Hexdump.toHexString(-1, 8));
        
        // Test different sizes
        assertEquals("00", Hexdump.toHexString(0, 2));
        assertEquals("FF", Hexdump.toHexString(255, 2));
        assertEquals("1234", Hexdump.toHexString(0x1234, 4));
    }

    @Test
    @DisplayName("Should convert long to hex string with padding")
    void testLongToHexString() {
        // Test various long values
        assertEquals("0000000000000000", Hexdump.toHexString(0L, 16));
        assertEquals("00000000000000FF", Hexdump.toHexString(255L, 16));
        assertEquals("FFFFFFFFFFFFFFFF", Hexdump.toHexString(-1L, 16));
        
        // Test different sizes
        assertEquals("00000000", Hexdump.toHexString(0L, 8));
        assertEquals("12345678", Hexdump.toHexString(0x12345678L, 8));
    }

    @Test
    @DisplayName("Should handle special byte values correctly")
    void testSpecialByteValues() {
        // Test boundary values
        byte[] data = { 
            (byte) 0x00,  // min value
            (byte) 0xFF,  // max value (-1 as signed byte)
            (byte) 0x7F,  // max positive
            (byte) 0x80   // min negative
        };
        
        String result = Hexdump.toHexString(data);
        assertEquals("00FF7F80", result);
    }

    @Test
    @DisplayName("Should handle large byte arrays efficiently")
    void testLargeByteArray() {
        // Create a larger test array
        byte[] data = createTestData(1024);
        
        // Test full array conversion
        String result = Hexdump.toHexString(data);
        assertEquals(2048, result.length()); // 1024 bytes * 2 chars
        
        // Test partial conversion
        String partial = Hexdump.toHexString(data, 512, 256);
        assertEquals(512, partial.length()); // 256 bytes * 2 chars
        assertTrue(partial.startsWith("00010203")); // 512 % 256 = 0, so starts at 0
    }
}