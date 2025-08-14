package jcifs.smb1.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@link Base64}.
 *
 * These tests cover the public static encode/decode methods for different
 * payload sizes, padding rules, and error conditions such as null and empty
 * input.
 */
@ExtendWith(MockitoExtension.class)
class Base64Test {

    /**
     * Data provider for various byte arrays and the expected Base64 string.
     */
    static Stream<Arguments> encodeProvider() {
        return Stream.of(Arguments.of(new byte[0], ""), Arguments.of(new byte[] { (byte) 0x41 }, "QQ=="), // "A"
                Arguments.of(new byte[] { (byte) 0x41, (byte) 0x42 }, "QUI="), // "AB"
                Arguments.of("Man".getBytes(), "TWFu"), // 3 bytes, no padding
                Arguments.of(new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00 }, "AAAA"), // all zeros
                Arguments.of(new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff }, "////")) // all 0xFF bytes
        ;
    }

    @ParameterizedTest(name = "encode({1}) -> {2}")
    @MethodSource("encodeProvider")
    void testEncode(byte[] input, String expected) {
        // Arrange & Act
        String actual = Base64.encode(input);
        // Assert
        assertEquals(expected, actual, "Base64.encode should match expected string");
    }

    /**
     * Data provider for Base64 strings and expected decoded byte arrays.
     */
    static Stream<Arguments> decodeProvider() {
        return Stream.of(Arguments.of("", new byte[0]), Arguments.of("QQ==", new byte[] { (byte) 0x41 }), // "A"
                Arguments.of("QUI=", new byte[] { (byte) 0x41, (byte) 0x42 }), // "AB"
                Arguments.of("TWFu", "Man".getBytes()), Arguments.of("AAAA", new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00 }), // all zeros
                Arguments.of("////", new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff })); // all 0xFF bytes
    }

    @ParameterizedTest(name = "decode({1}) -> {2}")
    @MethodSource("decodeProvider")
    void testDecode(String encoded, byte[] expected) {
        // Act
        byte[] actual = Base64.decode(encoded);
        // Assert
        assertArrayEquals(expected, actual, "Base64.decode should return original bytes");
    }

    @Test
    @DisplayName("encode should throw NPE on null input")
    void testEncodeNull() {
        assertThrows(NullPointerException.class, () -> Base64.encode(null));
    }

    @Test
    @DisplayName("decode should throw NPE on null input")
    void testDecodeNull() {
        assertThrows(NullPointerException.class, () -> Base64.decode(null));
    }
}
