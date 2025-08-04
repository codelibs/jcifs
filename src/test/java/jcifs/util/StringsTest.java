package jcifs.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import jcifs.Configuration;
import jcifs.RuntimeCIFSException;
import jcifs.util.Strings;

/**
 * Comprehensive test suite for Strings utility class.
 * Tests all string encoding/decoding operations and utility methods.
 */
@DisplayName("Strings Utility Tests")
class StringsTest {

    private static final String TEST_STRING = "Hello World";
    private static final String UNICODE_STRING = "Hello 世界 🌍";
    private static final String ASCII_STRING = "ASCII Test";

    @Nested
    @DisplayName("Basic Encoding Methods")
    class BasicEncodingTests {

        @Test
        @DisplayName("getBytes should handle null string")
        void testGetBytesWithNull() {
            // When
            byte[] result = Strings.getBytes(null, StandardCharsets.UTF_8);

            // Then
            assertNotNull(result, "Should return non-null array");
            assertEquals(0, result.length, "Should return empty array for null string");
        }

        @Test
        @DisplayName("getBytes should encode string with specified charset")
        void testGetBytesWithCharset() {
            // When
            byte[] utf8Bytes = Strings.getBytes(TEST_STRING, StandardCharsets.UTF_8);
            byte[] utf16Bytes = Strings.getBytes(TEST_STRING, StandardCharsets.UTF_16LE);

            // Then
            assertNotNull(utf8Bytes, "UTF-8 bytes should not be null");
            assertNotNull(utf16Bytes, "UTF-16LE bytes should not be null");
            assertTrue(utf8Bytes.length > 0, "UTF-8 bytes should not be empty");
            assertTrue(utf16Bytes.length > 0, "UTF-16LE bytes should not be empty");
            assertNotEquals(utf8Bytes.length, utf16Bytes.length, "Different encodings should produce different lengths");
        }

        @ParameterizedTest
        @DisplayName("getBytes should handle various string inputs")
        @NullAndEmptySource
        @ValueSource(strings = { "Simple ASCII", "Special chars: !@#$%^&*()", "Unicode: ñöt ascii ℃", "Mixed: ASCII + 中文 + Русский",
                "Emojis: 🎉🌟💻", "Very long string with multiple words and various characters 1234567890" })
        void testGetBytesWithVariousInputs(String input) {
            // When
            byte[] result = Strings.getBytes(input, StandardCharsets.UTF_8);

            // Then
            assertNotNull(result, "Result should never be null");
            if (input == null || input.isEmpty()) {
                assertEquals(0, result.length, "Null or empty input should produce empty array");
            } else {
                assertTrue(result.length > 0, "Non-empty input should produce non-empty array");
            }
        }
    }

    @Nested
    @DisplayName("Unicode and ASCII Encoding")
    class UnicodeAndASCIITests {

        @Test
        @DisplayName("getUNIBytes should encode string as UTF-16LE")
        void testGetUNIBytes() {
            // When
            byte[] result = Strings.getUNIBytes(TEST_STRING);

            // Then
            assertNotNull(result, "Result should not be null");
            assertTrue(result.length > 0, "Result should not be empty");
            assertEquals(TEST_STRING.getBytes(StandardCharsets.UTF_16LE).length, result.length, "Length should match UTF-16LE encoding");
            assertArrayEquals(TEST_STRING.getBytes(StandardCharsets.UTF_16LE), result, "Should produce same bytes as UTF-16LE encoding");
        }

        @Test
        @DisplayName("getUNIBytes should handle Unicode characters correctly")
        void testGetUNIBytesWithUnicode() {
            // When
            byte[] result = Strings.getUNIBytes(UNICODE_STRING);

            // Then
            assertNotNull(result, "Result should not be null");
            assertTrue(result.length > 0, "Result should not be empty");

            // Verify round-trip conversion
            String roundTrip = new String(result, StandardCharsets.UTF_16LE);
            assertEquals(UNICODE_STRING, roundTrip, "Round-trip conversion should preserve Unicode");
        }

        @Test
        @DisplayName("getASCIIBytes should encode string as ASCII")
        void testGetASCIIBytes() {
            // When
            byte[] result = Strings.getASCIIBytes(ASCII_STRING);

            // Then
            assertNotNull(result, "Result should not be null");
            assertTrue(result.length > 0, "Result should not be empty");
            assertEquals(ASCII_STRING.getBytes(StandardCharsets.US_ASCII).length, result.length, "Length should match ASCII encoding");
            assertArrayEquals(ASCII_STRING.getBytes(StandardCharsets.US_ASCII), result, "Should produce same bytes as ASCII encoding");
        }
    }

    @Nested
    @DisplayName("OEM Encoding Tests")
    class OEMEncodingTests {

        @Test
        @DisplayName("getOEMBytes should use configuration encoding")
        void testGetOEMBytes() {
            // Given
            Configuration mockConfig = mock(Configuration.class);
            when(mockConfig.getOemEncoding()).thenReturn("UTF-8");

            // When
            byte[] result = Strings.getOEMBytes(TEST_STRING, mockConfig);

            // Then
            assertNotNull(result, "Result should not be null");
            assertTrue(result.length > 0, "Result should not be empty");
            verify(mockConfig).getOemEncoding();
        }

        @Test
        @DisplayName("getOEMBytes should handle null string")
        void testGetOEMBytesWithNull() {
            // Given
            Configuration mockConfig = mock(Configuration.class);

            // When
            byte[] result = Strings.getOEMBytes(null, mockConfig);

            // Then
            assertNotNull(result, "Should return non-null array");
            assertEquals(0, result.length, "Should return empty array for null string");
            verify(mockConfig, never()).getOemEncoding();
        }

        @Test
        @DisplayName("getOEMBytes should throw RuntimeCIFSException for unsupported encoding")
        void testGetOEMBytesWithUnsupportedEncoding() {
            // Given
            Configuration mockConfig = mock(Configuration.class);
            when(mockConfig.getOemEncoding()).thenReturn("INVALID-ENCODING");

            // When & Then
            RuntimeCIFSException exception = assertThrows(RuntimeCIFSException.class, () -> {
                Strings.getOEMBytes(TEST_STRING, mockConfig);
            });

            assertTrue(exception.getMessage().contains("Unsupported OEM encoding"), "Exception should mention unsupported encoding");
            assertTrue(exception.getCause() instanceof UnsupportedEncodingException, "Cause should be UnsupportedEncodingException");
        }
    }

    @Nested
    @DisplayName("Unicode Decoding Tests")
    class UnicodeDecodingTests {

        @Test
        @DisplayName("fromUNIBytes should decode UTF-16LE bytes to string")
        void testFromUNIBytes() {
            // Given
            byte[] bytes = TEST_STRING.getBytes(StandardCharsets.UTF_16LE);

            // When
            String result = Strings.fromUNIBytes(bytes, 0, bytes.length);

            // Then
            assertEquals(TEST_STRING, result, "Should decode back to original string");
        }

        @Test
        @DisplayName("fromUNIBytes should handle partial byte arrays")
        void testFromUNIBytesPartial() {
            // Given
            String originalString = "Hello World Test";
            byte[] allBytes = originalString.getBytes(StandardCharsets.UTF_16LE);
            int partialLength = "Hello World".getBytes(StandardCharsets.UTF_16LE).length;

            // When
            String result = Strings.fromUNIBytes(allBytes, 0, partialLength);

            // Then
            assertEquals("Hello World", result, "Should decode partial byte array correctly");
        }

        @Test
        @DisplayName("fromUNIBytes should handle offset in byte array")
        void testFromUNIBytesWithOffset() {
            // Given
            String prefix = "PREFIX";
            String target = "TARGET";
            String combined = prefix + target;
            byte[] combinedBytes = combined.getBytes(StandardCharsets.UTF_16LE);
            int prefixBytes = prefix.getBytes(StandardCharsets.UTF_16LE).length;
            int targetBytes = target.getBytes(StandardCharsets.UTF_16LE).length;

            // When
            String result = Strings.fromUNIBytes(combinedBytes, prefixBytes, targetBytes);

            // Then
            assertEquals(target, result, "Should decode from offset correctly");
        }
    }

    @Nested
    @DisplayName("String Termination Tests")
    class StringTerminationTests {

        @Test
        @DisplayName("findUNITermination should find null termination in UTF-16LE")
        void testFindUNITermination() {
            // Given
            String testString = "Hello";
            byte[] stringBytes = testString.getBytes(StandardCharsets.UTF_16LE);
            byte[] bufferWithTermination = new byte[stringBytes.length + 2]; // +2 for null termination
            System.arraycopy(stringBytes, 0, bufferWithTermination, 0, stringBytes.length);
            bufferWithTermination[stringBytes.length] = 0x00;
            bufferWithTermination[stringBytes.length + 1] = 0x00;

            // When
            int terminationPos = Strings.findUNITermination(bufferWithTermination, 0, bufferWithTermination.length);

            // Then
            assertEquals(stringBytes.length, terminationPos, "Should find termination at correct position");
        }

        @Test
        @DisplayName("findUNITermination should throw exception when termination not found")
        void testFindUNITerminationNotFound() {
            // Given
            byte[] bufferWithoutTermination = "Hello".getBytes(StandardCharsets.UTF_16LE);

            // When & Then - the implementation throws ArrayIndexOutOfBoundsException when buffer bounds are exceeded
            assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
                Strings.findUNITermination(bufferWithoutTermination, 0, bufferWithoutTermination.length);
            }, "Should throw ArrayIndexOutOfBoundsException when termination not found within bounds");
        }

        @Test
        @DisplayName("findTermination should find null termination in single-byte encoding")
        void testFindTermination() {
            // Given
            String testString = "Hello";
            byte[] stringBytes = testString.getBytes(StandardCharsets.UTF_8);
            byte[] bufferWithTermination = new byte[stringBytes.length + 1]; // +1 for null termination
            System.arraycopy(stringBytes, 0, bufferWithTermination, 0, stringBytes.length);
            bufferWithTermination[stringBytes.length] = 0x00;

            // When
            int terminationPos = Strings.findTermination(bufferWithTermination, 0, bufferWithTermination.length);

            // Then
            assertEquals(stringBytes.length, terminationPos, "Should find termination at correct position");
        }

        @Test
        @DisplayName("findTermination should throw exception when termination not found")
        void testFindTerminationNotFound() {
            // Given
            byte[] bufferWithoutTermination = "Hello".getBytes(StandardCharsets.UTF_8);

            // When & Then - the implementation throws ArrayIndexOutOfBoundsException when buffer bounds are exceeded
            assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
                Strings.findTermination(bufferWithoutTermination, 0, bufferWithoutTermination.length);
            }, "Should throw ArrayIndexOutOfBoundsException when termination not found within bounds");
        }
    }

    @Nested
    @DisplayName("OEM Decoding Tests")
    class OEMDecodingTests {

        @Test
        @DisplayName("fromOEMBytes should decode using configuration encoding")
        void testFromOEMBytes() {
            // Given
            Configuration mockConfig = mock(Configuration.class);
            when(mockConfig.getOemEncoding()).thenReturn("UTF-8");
            byte[] bytes = TEST_STRING.getBytes(StandardCharsets.UTF_8);

            // When
            String result = Strings.fromOEMBytes(bytes, 0, bytes.length, mockConfig);

            // Then
            assertEquals(TEST_STRING, result, "Should decode using OEM encoding");
            verify(mockConfig).getOemEncoding();
        }

        @Test
        @DisplayName("fromOEMBytes should throw exception for unsupported encoding")
        void testFromOEMBytesWithUnsupportedEncoding() {
            // Given
            Configuration mockConfig = mock(Configuration.class);
            when(mockConfig.getOemEncoding()).thenReturn("INVALID-ENCODING");
            byte[] bytes = TEST_STRING.getBytes(StandardCharsets.UTF_8);

            // When & Then
            RuntimeCIFSException exception = assertThrows(RuntimeCIFSException.class, () -> {
                Strings.fromOEMBytes(bytes, 0, bytes.length, mockConfig);
            });

            assertTrue(exception.getMessage().contains("Unsupported OEM encoding"), "Exception should mention unsupported encoding");
            assertTrue(exception.getCause() instanceof UnsupportedEncodingException, "Cause should be UnsupportedEncodingException");
        }
    }

    @Nested
    @DisplayName("Secret Masking Tests")
    class SecretMaskingTests {

        @ParameterizedTest
        @DisplayName("maskSecretValue should mask SMB URLs containing credentials")
        @CsvSource({ "'smb://user:password@server/share', 'smb://user:******@server/share'",
                "'smb://domain\\user:secret@host/path', 'smb://domain\\user:******@host/path'",
                "'smb2://admin:admin123@192.168.1.1/folder', 'smb2://admin:******@192.168.1.1/folder'",
                "'smbs://test:p@ssw0rd@example.com/share', 'smbs://test:******@example.com/share'" })
        void testMaskSecretValueWithCredentials(String input, String expected) {
            // When
            String result = Strings.maskSecretValue(input);

            // Then
            assertEquals(expected, result, "Should mask password in SMB URL");
        }

        @ParameterizedTest
        @DisplayName("maskSecretValue should not mask non-SMB URLs or URLs without credentials")
        @ValueSource(strings = { "http://user:password@server/path", "smb://server/share", "smb://server/share/file.txt",
                "regular string with no URL", "smb://server:445/share" })
        void testMaskSecretValueWithoutCredentials(String input) {
            // When
            String result = Strings.maskSecretValue(input);

            // Then
            assertEquals(input, result, "Should not modify non-matching strings");
        }

        @Test
        @DisplayName("maskSecretValue should handle null input")
        void testMaskSecretValueWithNull() {
            // When
            String result = Strings.maskSecretValue(null);

            // Then
            assertNull(result, "Should return null for null input");
        }
    }

    @Nested
    @DisplayName("Comprehensive Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("All encoding methods should handle empty strings")
        void testEncodingMethodsWithEmptyString() {
            // Given
            Configuration mockConfig = mock(Configuration.class);
            when(mockConfig.getOemEncoding()).thenReturn("UTF-8");

            // When
            byte[] uniBytes = Strings.getUNIBytes("");
            byte[] asciiBytes = Strings.getASCIIBytes("");
            byte[] oemBytes = Strings.getOEMBytes("", mockConfig);

            // Then
            assertNotNull(uniBytes, "UNI bytes should not be null");
            assertNotNull(asciiBytes, "ASCII bytes should not be null");
            assertNotNull(oemBytes, "OEM bytes should not be null");
            assertEquals(0, uniBytes.length, "UNI bytes should be empty");
            assertEquals(0, asciiBytes.length, "ASCII bytes should be empty");
            assertEquals(0, oemBytes.length, "OEM bytes should be empty");
        }

        @Test
        @DisplayName("Round-trip encoding/decoding should preserve string content")
        void testRoundTripConversion() {
            // Given
            String[] testStrings = { "Simple ASCII", "Unicode: 世界 🌍", "Mixed: ASCII + Unicode ñöt", "Special chars: !@#$%^&*()", "" };

            for (String original : testStrings) {
                // When - round trip through UNI encoding
                byte[] uniBytes = Strings.getUNIBytes(original);
                String uniRoundTrip = Strings.fromUNIBytes(uniBytes, 0, uniBytes.length);

                // When - round trip through ASCII encoding (for ASCII-safe strings)
                if (original.chars().allMatch(c -> c < 128)) {
                    byte[] asciiBytes = Strings.getASCIIBytes(original);
                    String asciiRoundTrip = new String(asciiBytes, StandardCharsets.US_ASCII);
                    assertEquals(original, asciiRoundTrip, "ASCII round-trip should preserve content");
                }

                // Then
                assertEquals(original, uniRoundTrip, "UNI round-trip should preserve content: " + original);
            }
        }

        @Test
        @DisplayName("Strings utility class should not be instantiable")
        void testUtilityClassNotInstantiable() {
            // Given - Strings is a utility class with private constructor

            // When & Then - verify constructor is private by reflection
            assertDoesNotThrow(() -> {
                java.lang.reflect.Constructor<Strings> constructor = Strings.class.getDeclaredConstructor();
                assertTrue(java.lang.reflect.Modifier.isPrivate(constructor.getModifiers()), "Constructor should be private");
            }, "Should be able to access private constructor via reflection");
        }
    }
}