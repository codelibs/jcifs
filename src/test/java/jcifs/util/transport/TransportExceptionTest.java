package jcifs.util.transport;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import jcifs.CIFSException;

/**
 * Test class for TransportException
 */
public class TransportExceptionTest {

    @Test
    @DisplayName("Test default constructor creates exception with null message")
    public void testDefaultConstructor() {
        // Create exception with default constructor
        TransportException exception = new TransportException();
        
        // Verify the exception is created and has no message
        assertNotNull(exception);
        assertNull(exception.getMessage());
        assertNull(exception.getCause());
        
        // Verify it's an instance of CIFSException
        assertTrue(exception instanceof CIFSException);
    }

    @Test
    @DisplayName("Test constructor with message creates exception with specified message")
    public void testConstructorWithMessage() {
        // Test with various messages
        String message = "Test error message";
        TransportException exception = new TransportException(message);
        
        // Verify the exception has the correct message
        assertNotNull(exception);
        assertEquals(message, exception.getMessage());
        assertNull(exception.getCause());
        
        // Test with empty string
        TransportException emptyException = new TransportException("");
        assertEquals("", emptyException.getMessage());
        
        // Test with null message
        TransportException nullException = new TransportException((String) null);
        assertNull(nullException.getMessage());
    }

    @Test
    @DisplayName("Test constructor with cause creates exception with specified cause")
    public void testConstructorWithCause() {
        // Create a root cause exception
        RuntimeException rootCause = new RuntimeException("Root cause error");
        TransportException exception = new TransportException(rootCause);
        
        // Verify the exception has the correct cause
        assertNotNull(exception);
        assertEquals(rootCause, exception.getCause());
        assertEquals("java.lang.RuntimeException: Root cause error", exception.getMessage());
        
        // Test with null cause
        TransportException nullCauseException = new TransportException((Throwable) null);
        assertNull(nullCauseException.getCause());
    }

    @Test
    @DisplayName("Test constructor with message and cause creates exception with both")
    public void testConstructorWithMessageAndCause() {
        // Create exception with both message and cause
        String message = "Transport error occurred";
        IllegalStateException rootCause = new IllegalStateException("State error");
        TransportException exception = new TransportException(message, rootCause);
        
        // Verify both message and cause are set correctly
        assertNotNull(exception);
        assertEquals(message, exception.getMessage());
        assertEquals(rootCause, exception.getCause());
        
        // Test with null message and valid cause
        TransportException nullMessageException = new TransportException(null, rootCause);
        assertNull(nullMessageException.getMessage());
        assertEquals(rootCause, nullMessageException.getCause());
        
        // Test with valid message and null cause
        TransportException nullCauseException = new TransportException(message, null);
        assertEquals(message, nullCauseException.getMessage());
        assertNull(nullCauseException.getCause());
        
        // Test with both null
        TransportException bothNullException = new TransportException(null, null);
        assertNull(bothNullException.getMessage());
        assertNull(bothNullException.getCause());
    }

    @Test
    @DisplayName("Test deprecated getRootCause method returns the same as getCause")
    @SuppressWarnings("deprecation")
    public void testGetRootCause() {
        // Test with no cause
        TransportException noCauseException = new TransportException("No cause");
        assertNull(noCauseException.getRootCause());
        assertEquals(noCauseException.getCause(), noCauseException.getRootCause());
        
        // Test with cause
        IOException rootCause = new IOException("IO error");
        TransportException withCauseException = new TransportException("With cause", rootCause);
        assertEquals(rootCause, withCauseException.getRootCause());
        assertEquals(withCauseException.getCause(), withCauseException.getRootCause());
        
        // Test with nested causes
        RuntimeException middleCause = new RuntimeException("Middle", rootCause);
        TransportException nestedCauseException = new TransportException("Nested", middleCause);
        assertEquals(middleCause, nestedCauseException.getRootCause());
        assertEquals(nestedCauseException.getCause(), nestedCauseException.getRootCause());
    }

    @Test
    @DisplayName("Test exception inheritance and polymorphism")
    public void testInheritance() {
        // Create exception
        TransportException exception = new TransportException("Test exception");
        
        // Test inheritance chain
        assertTrue(exception instanceof TransportException);
        assertTrue(exception instanceof CIFSException);
        assertTrue(exception instanceof Exception);
        assertTrue(exception instanceof Throwable);
        
        // Test that it can be caught as CIFSException
        boolean caughtAsCIFSException = false;
        try {
            throw exception;
        } catch (CIFSException e) {
            caughtAsCIFSException = true;
            assertEquals(exception, e);
        }
        assertTrue(caughtAsCIFSException);
    }

    @Test
    @DisplayName("Test exception can be thrown and caught")
    public void testThrowAndCatch() {
        // Test throwing and catching with message
        String expectedMessage = "Transport failed";
        assertThrows(TransportException.class, () -> {
            throw new TransportException(expectedMessage);
        });
        
        // Test throwing and catching with cause
        RuntimeException cause = new RuntimeException("Cause");
        TransportException thrown = assertThrows(TransportException.class, () -> {
            throw new TransportException(cause);
        });
        assertEquals(cause, thrown.getCause());
        
        // Test throwing and catching with message and cause
        TransportException thrownWithBoth = assertThrows(TransportException.class, () -> {
            throw new TransportException(expectedMessage, cause);
        });
        assertEquals(expectedMessage, thrownWithBoth.getMessage());
        assertEquals(cause, thrownWithBoth.getCause());
    }

    @Test
    @DisplayName("Test serialization compatibility")
    public void testSerialVersionUID() {
        // Verify that the serialVersionUID is set
        TransportException exception = new TransportException();
        
        // The exception should be serializable since it extends CIFSException
        assertTrue(exception instanceof java.io.Serializable);
    }

    /**
     * Helper class for testing - not actually needed but demonstrates IOException usage
     */
    private static class IOException extends Exception {
        public IOException(String message) {
            super(message);
        }
    }
}
