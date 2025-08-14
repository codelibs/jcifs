package jcifs.pac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import org.junit.jupiter.api.Test;

/**
 * Tests for the PACDecodingException class.
 */
class PACDecodingExceptionTest {

    /**
     * Test the default constructor.
     */
    @Test
    void testDefaultConstructor() {
        PACDecodingException e = new PACDecodingException();
        // Expect null message and null cause
        assertNull(e.getMessage());
        assertNull(e.getCause());
    }

    /**
     * Test the constructor with a message.
     */
    @Test
    void testMessageConstructor() {
        String errorMessage = "This is a test error message.";
        PACDecodingException e = new PACDecodingException(errorMessage);
        // Expect the message to be set correctly and cause to be null
        assertEquals(errorMessage, e.getMessage());
        assertNull(e.getCause());
    }

    /**
     * Test the constructor with a cause.
     */
    @Test
    void testCauseConstructor() {
        Throwable cause = new RuntimeException("Root cause");
        PACDecodingException e = new PACDecodingException(cause);
        // When constructed with only a cause, the implementation passes (null, cause) to super
        // which results in a null message rather than deriving it from the cause
        assertNull(e.getMessage());
        assertSame(cause, e.getCause());
    }

    /**
     * Test the constructor with both a message and a cause.
     */
    @Test
    void testMessageAndCauseConstructor() {
        String errorMessage = "This is a test error message.";
        Throwable cause = new RuntimeException("Root cause");
        PACDecodingException e = new PACDecodingException(errorMessage, cause);
        // Expect both the message and the cause to be set correctly
        assertEquals(errorMessage, e.getMessage());
        assertSame(cause, e.getCause());
    }
}
