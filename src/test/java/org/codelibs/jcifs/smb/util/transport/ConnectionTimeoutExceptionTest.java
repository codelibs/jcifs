package org.codelibs.jcifs.smb.util.transport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class ConnectionTimeoutExceptionTest {

    @Test
    void testNoArgsConstructor() {
        // Test the no-argument constructor
        ConnectionTimeoutException exception = new ConnectionTimeoutException();
        assertNull(exception.getMessage(), "Message should be null for no-arg constructor");
        assertNull(exception.getCause(), "Cause should be null for no-arg constructor");
    }

    @Test
    void testStringConstructor() {
        // Test the constructor with a message
        String message = "Connection timed out.";
        ConnectionTimeoutException exception = new ConnectionTimeoutException(message);
        assertEquals(message, exception.getMessage(), "Message should match the provided string");
        assertNull(exception.getCause(), "Cause should be null for string constructor");
    }

    @Test
    void testThrowableConstructor() {
        // Test the constructor with a cause
        Throwable cause = new RuntimeException("Root cause of timeout");
        ConnectionTimeoutException exception = new ConnectionTimeoutException(cause);
        assertEquals("java.lang.RuntimeException: Root cause of timeout", exception.getMessage(),
                "Message should be derived from the cause");
        assertEquals(cause, exception.getCause(), "Cause should match the provided throwable");
    }

    @Test
    void testStringAndThrowableConstructor() {
        // Test the constructor with both message and cause
        String message = "Failed to connect due to timeout.";
        Throwable cause = new IllegalStateException("Network unreachable");
        ConnectionTimeoutException exception = new ConnectionTimeoutException(message, cause);
        assertEquals(message, exception.getMessage(), "Message should match the provided string");
        assertEquals(cause, exception.getCause(), "Cause should match the provided throwable");
    }
}
