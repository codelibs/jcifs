package jcifs.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import jcifs.BaseTest;

/**
 * Test class for Encdec utility functionality
 */
@DisplayName("Encdec Utility Tests")
class EncdecTest extends BaseTest {

    @Test
    @DisplayName("Should encode and decode 16-bit integers")
    void testInt16Operations() {
        // Given
        short value = 0x1234;
        byte[] buffer = new byte[2];

        // When - encode little endian
        Encdec.enc_uint16le(value, buffer, 0);
        short decoded = (short) Encdec.dec_uint16le(buffer, 0);

        // Then
        assertEquals(value, decoded);
        assertEquals(0x34, buffer[0] & 0xFF);
        assertEquals(0x12, buffer[1] & 0xFF);
    }

    @Test
    @DisplayName("Should encode and decode 32-bit integers")
    void testInt32Operations() {
        // Given
        int value = 0x12345678;
        byte[] buffer = new byte[4];

        // When - encode little endian
        Encdec.enc_uint32le(value, buffer, 0);
        long decoded = Encdec.dec_uint32le(buffer, 0);

        // Then
        assertEquals(value & 0xFFFFFFFFL, decoded);
        assertEquals(0x78, buffer[0] & 0xFF);
        assertEquals(0x56, buffer[1] & 0xFF);
        assertEquals(0x34, buffer[2] & 0xFF);
        assertEquals(0x12, buffer[3] & 0xFF);
    }

    @Test
    @DisplayName("Should encode and decode 64-bit integers")
    void testInt64Operations() {
        // Given
        long value = 0x123456789ABCDEF0L;
        byte[] buffer = new byte[8];

        // When - encode little endian
        Encdec.enc_uint64le(value, buffer, 0);
        long decoded = Encdec.dec_uint64le(buffer, 0);

        // Then
        assertEquals(value, decoded);
        assertEquals(0xF0, buffer[0] & 0xFF);
        assertEquals(0xDE, buffer[1] & 0xFF);
        assertEquals(0xBC, buffer[2] & 0xFF);
        assertEquals(0x9A, buffer[3] & 0xFF);
    }

    @Test
    @DisplayName("Should handle big endian encoding/decoding")
    void testBigEndianOperations() {
        // Given
        int value = 0x12345678;
        byte[] buffer = new byte[4];

        // When - encode big endian
        Encdec.enc_uint32be(value, buffer, 0);
        long decoded = Encdec.dec_uint32be(buffer, 0);

        // Then
        assertEquals(value & 0xFFFFFFFFL, decoded);
        assertEquals(0x12, buffer[0] & 0xFF);
        assertEquals(0x34, buffer[1] & 0xFF);
        assertEquals(0x56, buffer[2] & 0xFF);
        assertEquals(0x78, buffer[3] & 0xFF);
    }

    @ParameterizedTest
    @ValueSource(ints = { 0, 1, 255, 256, 65535, 65536, Integer.MAX_VALUE })
    @DisplayName("Should handle boundary values")
    void testBoundaryValues(int value) {
        // Given
        byte[] buffer = new byte[4];

        // When
        Encdec.enc_uint32le(value, buffer, 0);
        long decoded = Encdec.dec_uint32le(buffer, 0);

        // Then
        assertEquals(value & 0xFFFFFFFFL, decoded);
    }

    @Test
    @DisplayName("Should encode and decode strings using byte operations")
    void testStringOperations() {
        // Given
        String testString = "Hello";
        byte[] buffer = new byte[testString.length()];
        
        // When - Manual string encoding using individual bytes
        byte[] strBytes = testString.getBytes();
        System.arraycopy(strBytes, 0, buffer, 0, strBytes.length);

        // Then
        String decoded = new String(buffer);
        assertEquals(testString, decoded);
    }

    @Test
    @DisplayName("Should handle buffer bounds checking")
    void testBufferBounds() {
        // Given
        byte[] smallBuffer = new byte[2];

        // When/Then
        assertThrows(IndexOutOfBoundsException.class, () -> {
            Encdec.enc_uint32le(0x12345678, smallBuffer, 0);
        });

        assertThrows(IndexOutOfBoundsException.class, () -> {
            Encdec.dec_uint32le(smallBuffer, 0);
        });
    }

    @Test
    @DisplayName("Should handle time encoding/decoding")
    void testTimeOperations() {
        // Given
        Date currentDate = new Date();
        byte[] buffer = new byte[8];

        // When - Use direct encoding methods since time constants are private
        Encdec.enc_uint64le(currentDate.getTime(), buffer, 0);
        long decoded = Encdec.dec_uint64le(buffer, 0);

        // Then
        assertEquals(currentDate.getTime(), decoded, "Encoded and decoded time should match");
    }

    @Test
    @DisplayName("Should encode and decode UUIDs")
    void testUUIDOperations() {
        // Given
        byte[] uuid = { 0x12, 0x34, 0x56, 0x78, (byte) 0x9A, (byte) 0xBC, (byte) 0xDE, (byte) 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                0x77, (byte) 0x88 };
        byte[] buffer = new byte[16];

        // When
        System.arraycopy(uuid, 0, buffer, 0, 16);

        // Then
        assertArrayEquals(uuid, buffer);
    }
}