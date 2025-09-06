package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests for SmbEndOfFileException focusing on message, status, and throwability.
 */
@ExtendWith(MockitoExtension.class)
class SmbEndOfFileExceptionTest {

    /**
     * Verifies the no-arg constructor sets the expected message, status, and no cause.
     */
    @Test
    void defaultConstructorSetsMessageAndStatus() {
        // Arrange & Act
        SmbEndOfFileException ex = new SmbEndOfFileException();

        // Assert
        assertEquals("Unexpectedly reached end of file", ex.getMessage(), "Default message must match");
        assertEquals(NtStatus.NT_STATUS_UNSUCCESSFUL, ex.getNtStatus(), "Default NT status should be UNSUCCESSFUL");
        assertNull(ex.getCause(), "Cause should be null by default");
        assertNull(ex.getRootCause(), "Root cause should be null by default");
        assertTrue(ex instanceof SmbException, "Should be an SmbSystemException subtype");
    }

    /**
     * Ensures the exception is thrown and captured via assertThrows with the right message.
     */
    @Test
    void assertThrowsCapturesExceptionAndMessage() {
        // Act & Assert
        SmbEndOfFileException thrown = assertThrows(SmbEndOfFileException.class, () -> {
            throw new SmbEndOfFileException();
        });
        assertEquals("Unexpectedly reached end of file", thrown.getMessage());
    }

    /**
     * toString should include both the class name and the default message.
     */
    @ParameterizedTest
    @ValueSource(strings = { "SmbEndOfFileException", "Unexpectedly reached end of file" })
    void toStringContainsKeyInfo(String expectedSubstring) {
        // Arrange
        SmbEndOfFileException ex = new SmbEndOfFileException();

        // Act
        String text = ex.toString();

        // Assert
        assertNotNull(text);
        assertTrue(text.contains(expectedSubstring), "toString should contain: " + expectedSubstring);
    }
}
