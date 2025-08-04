package jcifs.util.transport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class RequestTimeoutExceptionTest {

    @Test
    void testNoArgsConstructor() {
        // Test the constructor with no arguments
        RequestTimeoutException exception = new RequestTimeoutException();
        assertNull(exception.getMessage(), "Message should be null for no-arg constructor");
        assertNull(exception.getCause(), "Cause should be null for no-arg constructor");
    }

    @Test
    void testMessageConstructor() {
        // Test the constructor with a message argument
        String message = "Test message";
        RequestTimeoutException exception = new RequestTimeoutException(message);
        assertEquals(message, exception.getMessage(), "Message should match the provided string");
        assertNull(exception.getCause(), "Cause should be null for message-only constructor");
    }

    @Test
    void testCauseConstructor() {
        // Test the constructor with a cause argument
        Throwable cause = new RuntimeException("Root cause");
        RequestTimeoutException exception = new RequestTimeoutException(cause);
        assertEquals("java.lang.RuntimeException: Root cause", exception.getMessage(), "Message should be derived from the cause");
        assertEquals(cause, exception.getCause(), "Cause should match the provided throwable");
    }

    @Test
    void testMessageAndCauseConstructor() {
        // Test the constructor with both message and cause arguments
        String message = "Test message with cause";
        Throwable cause = new IllegalArgumentException("Invalid argument");
        RequestTimeoutException exception = new RequestTimeoutException(message, cause);
        assertEquals(message, exception.getMessage(), "Message should match the provided string");
        assertEquals(cause, exception.getCause(), "Cause should match the provided throwable");
    }

    @Test
    void testIsInstanceOfTransportException() {
        // Verify that RequestTimeoutException is a subclass of TransportException
        RequestTimeoutException exception = new RequestTimeoutException();
        assertTrue(exception instanceof TransportException, "RequestTimeoutException should be an instance of TransportException");
    }
}
