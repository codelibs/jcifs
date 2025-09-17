package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests for SMBProtocolDowngradeException covering all constructors and behaviors.
 */
@ExtendWith(MockitoExtension.class)
class SMBProtocolDowngradeExceptionTest {

    /**
     * Provides messages including edge cases (null and empty) for parameterized testing.
     */
    static Stream<Arguments> messages() {
        return Stream.of(Arguments.of((String) null), Arguments.of(""), Arguments.of("unexpected downgrade"));
    }

    @Test
    @DisplayName("Default ctor: null message/cause; toString is class name; type hierarchy")
    void defaultConstructor_hasNullMessageAndCause_andTypeHierarchy() {
        // Arrange & Act
        SMBProtocolDowngradeException ex = new SMBProtocolDowngradeException();

        // Assert - message and cause are null
        assertNull(ex.getMessage(), "Default constructor should have null message");
        assertNull(ex.getCause(), "Default constructor should have null cause");

        // Assert - toString shows class name when message is null
        assertEquals(SMBProtocolDowngradeException.class.getName(), ex.toString());

        // Assert - type hierarchy: subclass of CIFSException and IOException
        assertTrue(ex instanceof org.codelibs.jcifs.smb.CIFSException, "Should extend CIFSException");
        assertTrue(ex instanceof IOException, "Should be an IOException (checked)");
    }

    @ParameterizedTest(name = "Message-only ctor preserves message: [{0}]")
    @MethodSource("messages")
    void messageConstructor_setsMessageAndNullCause(String message) {
        // Arrange & Act
        SMBProtocolDowngradeException ex = new SMBProtocolDowngradeException(message);

        // Assert - message preserved, cause null
        assertEquals(message, ex.getMessage());
        assertNull(ex.getCause());

        // Assert - toString starts with class name and contains message when present
        if (message == null) {
            assertEquals(SMBProtocolDowngradeException.class.getName(), ex.toString());
        } else if (message.isEmpty()) {
            // Throwable.toString prints class + ": " (with space) even for empty string
            assertEquals(SMBProtocolDowngradeException.class.getName() + ": ", ex.toString());
        } else {
            assertEquals(SMBProtocolDowngradeException.class.getName() + ": " + message, ex.toString());
        }
    }

    @Test
    void causeConstructor_setsCause_andDerivesMessageFromCauseToString() {
        // Arrange - use a real cause so message is derived from cause.toString()
        Throwable cause = new IllegalStateException("proto mismatch");
        String expectedMessage = cause.toString();

        // Act
        SMBProtocolDowngradeException ex = new SMBProtocolDowngradeException(cause);

        // Assert - cause preserved, message derived from cause
        assertSame(cause, ex.getCause());
        assertEquals(expectedMessage, ex.getMessage());

        // toString should include the derived message
        assertEquals(SMBProtocolDowngradeException.class.getName() + ": " + expectedMessage, ex.toString());
    }

    @Test
    void messageAndCauseConstructor_setsMessageAndCause_withoutInteractingWithCause() {
        // Arrange - mock cause to verify no interactions are needed to construct
        Throwable cause = Mockito.mock(Throwable.class);
        String message = "forced downgrade detected";

        // Act
        SMBProtocolDowngradeException ex = new SMBProtocolDowngradeException(message, cause);

        // Assert - fields preserved
        assertSame(cause, ex.getCause());
        assertEquals(message, ex.getMessage());

        // Since message is explicitly provided, constructor should not need to call methods on cause
        Mockito.verifyNoInteractions(cause);

        // toString should include provided message
        assertEquals(SMBProtocolDowngradeException.class.getName() + ": " + message, ex.toString());
    }

    @Test
    void messageAndCauseConstructor_acceptsNullMessage_edgeCase() {
        // Arrange
        Throwable cause = new RuntimeException("root cause");

        // Act
        SMBProtocolDowngradeException ex = new SMBProtocolDowngradeException(null, cause);

        // Assert - null message retained; cause preserved
        assertNull(ex.getMessage());
        assertSame(cause, ex.getCause());
        assertEquals(SMBProtocolDowngradeException.class.getName(), ex.toString());
    }

    @Test
    void assertThrows_capturesExceptionAndMessage() {
        // Arrange
        String msg = "downgrade not allowed";

        // Act & Assert - verify thrown type and message
        SMBProtocolDowngradeException thrown = assertThrows(SMBProtocolDowngradeException.class, () -> {
            throw new SMBProtocolDowngradeException(msg);
        });
        assertEquals(msg, thrown.getMessage());
    }
}
