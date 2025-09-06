package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Test class for CIFSException functionality
 */
@DisplayName("CIFSException Tests")
class CIFSExceptionTest extends BaseTest {

    @Test
    @DisplayName("Should create CIFSException with message")
    void testCIFSExceptionWithMessage() {
        // Given
        String message = "CIFS operation failed";

        // When
        CIFSException exception = new CIFSException(message);

        // Then
        assertNotNull(exception);
        assertEquals(message, exception.getMessage());
        assertTrue(exception instanceof IOException);
    }

    @Test
    @DisplayName("Should create CIFSException with message and cause")
    void testCIFSExceptionWithCause() {
        // Given
        String message = "CIFS operation failed";
        Exception cause = new RuntimeException("Root cause");

        // When
        CIFSException exception = new CIFSException(message, cause);

        // Then
        assertNotNull(exception);
        assertEquals(message, exception.getMessage());
        assertEquals(cause, exception.getCause());
    }

    @Test
    @DisplayName("Should create CIFSException with cause only")
    void testCIFSExceptionWithCauseOnly() {
        // Given
        Exception cause = new RuntimeException("Root cause");

        // When
        CIFSException exception = new CIFSException(cause);

        // Then
        assertNotNull(exception);
        assertEquals(cause, exception.getCause());
        assertTrue(exception.getMessage().contains("Root cause"));
    }

    @Test
    @DisplayName("Should handle null message")
    void testNullMessage() {
        // When/Then
        assertDoesNotThrow(() -> {
            CIFSException exception = new CIFSException((String) null);
            assertNotNull(exception);
        });
    }

    @Test
    @DisplayName("Should handle null cause")
    void testNullCause() {
        // When/Then
        assertDoesNotThrow(() -> {
            CIFSException exception = new CIFSException("Message", null);
            assertNotNull(exception);
            assertEquals("Message", exception.getMessage());
            assertNull(exception.getCause());
        });
    }
}
