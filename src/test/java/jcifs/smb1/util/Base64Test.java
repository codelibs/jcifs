package jcifs.smb1.util;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.stream.Stream;

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
        return Stream.of(
            Arguments.of(new byte[0], ""),
            Arguments.of(new byte[]{ (byte) 0x41 }, "QQ=="), // "A"
            Arguments.of(new byte[]{ (byte) 0x41, (byte) 0x42 }, "QUI="), // "AB"
            Arguments.of("Man".getBytes(), "TWFu"), // 3 bytes, no padding
            Arguments.of("\u0000\u0000\u0000".getBytes(), "AAAA"), // all zeros
            Arguments.of("\u00ff\u00ff\u00ff".getBytes(), "///w=="))
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
        return Stream.of(
            Arguments.of("", new byte[0]),
            Arguments.of("QQ==", "A".getBytes()),
            Arguments.of("QUI=", "AB".getBytes()),
            Arguments.of("TWFu", "Man".getBytes()),
            Arguments.of("AAAA", "\0\0\0".getBytes()),
            Arguments.of("///w==", "\u00ff\u00ff\u00ff".getBytes()));
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

