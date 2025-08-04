package jcifs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Comprehensive test suite for CIFSUnsupportedCryptoException class.
 * Tests all constructors, inheritance behavior, and crypto-specific scenarios.
 */
@DisplayName("CIFSUnsupportedCryptoException Tests")
class CIFSUnsupportedCryptoExceptionTest extends BaseTest {

    private static final String CRYPTO_ERROR_MESSAGE = "Unsupported cryptographic algorithm: AES-256-GCM";
    private static final String ALGORITHM_NAME = "AES-256-GCM";

    @Test
    @DisplayName("Default constructor should create exception with null message and cause")
    void testDefaultConstructor() {
        // Given & When
        CIFSUnsupportedCryptoException exception = new CIFSUnsupportedCryptoException();

        // Then
        assertNull(exception.getMessage(), "Default constructor should have null message");
        assertNull(exception.getCause(), "Default constructor should have null cause");
        assertTrue(exception instanceof RuntimeCIFSException, "Should extend RuntimeCIFSException");
        assertTrue(exception instanceof RuntimeException, "Should be a RuntimeException");
    }

    @Test
    @DisplayName("Message constructor should create exception with specified message")
    void testMessageConstructor() {
        // Given & When
        CIFSUnsupportedCryptoException exception = new CIFSUnsupportedCryptoException(CRYPTO_ERROR_MESSAGE);

        // Then
        assertEquals(CRYPTO_ERROR_MESSAGE, exception.getMessage(), "Message should be preserved");
        assertNull(exception.getCause(), "Cause should be null when not specified");
    }

    @ParameterizedTest
    @DisplayName("Message constructor should handle crypto-specific error messages")
    @NullAndEmptySource
    @ValueSource(strings = { "AES encryption not supported", "Missing Bouncy Castle provider", "Invalid key length for AES-128",
            "RC4 cipher not available in this JVM", "DES encryption is deprecated and not supported", "HMAC-SHA256 algorithm not found",
            "RSA key generation failed: key size not supported" })
    void testMessageConstructorWithCryptoMessages(String message) {
        // Given & When
        CIFSUnsupportedCryptoException exception = new CIFSUnsupportedCryptoException(message);

        // Then
        assertEquals(message, exception.getMessage(), "Crypto message should be preserved exactly");
        assertNull(exception.getCause(), "Cause should be null");
    }

    @Test
    @DisplayName("Cause constructor should create exception with cryptographic cause")
    void testCauseConstructor() {
        // Given
        NoSuchAlgorithmException cause = new NoSuchAlgorithmException("AES-GCM algorithm not available");

        // When
        CIFSUnsupportedCryptoException exception = new CIFSUnsupportedCryptoException(cause);

        // Then
        assertSame(cause, exception.getCause(), "Crypto cause should be preserved");
        assertEquals(cause.toString(), exception.getMessage(), "Message should be cause.toString() when only cause is provided");
    }

    @Test
    @DisplayName("Message and cause constructor should preserve both crypto parameters")
    void testMessageAndCauseConstructor() {
        // Given
        NoSuchAlgorithmException cause = new NoSuchAlgorithmException("Algorithm not found");

        // When
        CIFSUnsupportedCryptoException exception = new CIFSUnsupportedCryptoException(CRYPTO_ERROR_MESSAGE, cause);

        // Then
        assertEquals(CRYPTO_ERROR_MESSAGE, exception.getMessage(), "Crypto message should be preserved");
        assertSame(cause, exception.getCause(), "Crypto cause should be preserved");
    }
}
