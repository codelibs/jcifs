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
        assertTrue(result.contains("00"));
        assertTrue(result.contains("0F"));
        assertTrue(result.contains("FF"));
        assertTrue(result.contains("7F"));
        assertTrue(result.contains("80"));
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
        assertEquals("", result.trim());
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
    @DisplayName("Should format hex dump with offsets")
    void testHexdumpWithOffset() {
        // Given
        byte[] data = createTestData(32);

        // When
        String result = Hexdump.toHexString(data, 0, data.length);

        // Then
        assertNotNull(result);
        assertFalse(result.isEmpty());
        // Should contain offset markers
        assertTrue(result.contains("00000000"));
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
            Hexdump.toHexString(data, 16, data.length);
        });
    }
}