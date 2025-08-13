package jcifs.internal;

import jcifs.CIFSException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for SMBProtocolDecodingException covering all constructors and observable behavior.
 */
@ExtendWith(MockitoExtension.class)
public class SMBProtocolDecodingExceptionTest {

    @Mock
    Throwable mockCause;

    @Test
    @DisplayName("No-arg constructor: null message and cause; can be thrown")
    void defaultConstructor_behavesAsExpected() {
        // Arrange & Act
        SMBProtocolDecodingException ex = new SMBProtocolDecodingException();

        // Assert state
        assertNull(ex.getMessage(), "Default constructor should have null message");
        assertNull(ex.getCause(), "Default constructor should have null cause");
        assertTrue(ex instanceof CIFSException, "Should be a CIFSException subtype");

        // Assert throwing/catching behavior with assertThrows
        SMBProtocolDecodingException thrown = assertThrows(
                SMBProtocolDecodingException.class,
                () -> { throw new SMBProtocolDecodingException(); },
                "Should be throwable via assertThrows");
        assertTrue(thrown instanceof CIFSException, "Thrown instance should also be CIFSException subtype");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"hello", " ", "unicode-∑"})
    @DisplayName("Message-only constructor: preserves provided message; null cause")
    void messageOnlyConstructor_preservesMessage(String message) {
        // Arrange & Act
        SMBProtocolDecodingException ex = new SMBProtocolDecodingException(message);

        // Assert message and cause
        assertEquals(message, ex.getMessage(), "Message should be preserved as provided");
        assertNull(ex.getCause(), "Cause should be null when only message is provided");

        // toString should include the class name and (if non-null) the message
        String ts = ex.toString();
        assertTrue(ts.contains("SMBProtocolDecodingException"), "toString should include class name");
        if (message != null && !message.isEmpty()) {
            assertTrue(ts.contains(message), "toString should include non-empty message");
        }
    }

    @Test
    @DisplayName("Cause-only constructor: preserves provided cause; no interactions with cause")
    void causeOnlyConstructor_preservesCause_andNoInteractions() {
        // Arrange & Act
        SMBProtocolDecodingException ex = new SMBProtocolDecodingException(mockCause);

        // Assert cause propagation
        assertSame(mockCause, ex.getCause(), "Cause should be exactly the provided instance");

        // Access common Throwable methods to exercise paths without touching the cause
        assertNotNull(ex.toString(), "toString should be non-null");
        ex.getMessage(); // don't assert content to avoid implementation assumptions

        // Verify no interactions happened with the mocked cause during construction/access
        verifyNoInteractions(mockCause);
    }

    @Test
    @DisplayName("Cause-only constructor with null: null cause maintained")
    void causeOnlyConstructor_acceptsNull() {
        // Arrange & Act
        SMBProtocolDecodingException ex = new SMBProtocolDecodingException((Throwable) null);

        // Assert
        assertNull(ex.getCause(), "Null cause should be preserved");
        assertNotNull(ex.toString(), "toString should be safe to call");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"oops", "multi word", "中文"})
    @DisplayName("Message+Cause constructor: preserves both values; no interactions with cause")
    void messageAndCauseConstructor_preservesBoth(String message) {
        // Arrange & Act
        SMBProtocolDecodingException ex = new SMBProtocolDecodingException(message, mockCause);

        // Assert message and cause
        assertEquals(message, ex.getMessage(), "Message should be preserved as provided");
        assertSame(mockCause, ex.getCause(), "Cause should be exactly the provided instance");

        // toString should include class name and, when present, the message
        String ts = ex.toString();
        assertTrue(ts.contains("SMBProtocolDecodingException"), "toString should include class name");
        if (message != null && !message.isEmpty()) {
            assertTrue(ts.contains(message), "toString should include non-empty message");
        }

        // Ensure constructors/getters don't interact with the cause
        verifyNoInteractions(mockCause);
    }
}

