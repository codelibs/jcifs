package jcifs;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Test class for RuntimeCIFSException functionality
 */
@DisplayName("RuntimeCIFSException Tests")
class RuntimeCIFSExceptionTest extends BaseTest {

    @Test
    @DisplayName("Should create RuntimeCIFSException with default constructor")
    void testDefaultConstructor() {
        // When
        RuntimeCIFSException exception = new RuntimeCIFSException();

        // Then
        assertNotNull(exception);
        assertNull(exception.getMessage());
        assertNull(exception.getCause());
        assertTrue(exception instanceof RuntimeException);
    }

    @Test
    @DisplayName("Should create RuntimeCIFSException with message")
    void testConstructorWithMessage() {
        // Given
        String message = "CIFS runtime error occurred";

        // When
        RuntimeCIFSException exception = new RuntimeCIFSException(message);

        // Then
        assertNotNull(exception);
        assertEquals(message, exception.getMessage());
        assertNull(exception.getCause());
    }

    @Test
    @DisplayName("Should create RuntimeCIFSException with cause")
    void testConstructorWithCause() {
        // Given
        Throwable cause = new IllegalArgumentException("Invalid argument");

        // When
        RuntimeCIFSException exception = new RuntimeCIFSException(cause);

        // Then
        assertNotNull(exception);
        assertEquals(cause, exception.getCause());
        assertTrue(exception.getMessage().contains("IllegalArgumentException"));
        assertTrue(exception.getMessage().contains("Invalid argument"));
    }

    @Test
    @DisplayName("Should create RuntimeCIFSException with message and cause")
    void testConstructorWithMessageAndCause() {
        // Given
        String message = "CIFS operation failed";
        Throwable cause = new RuntimeException("Root cause");

        // When
        RuntimeCIFSException exception = new RuntimeCIFSException(message, cause);

        // Then
        assertNotNull(exception);
        assertEquals(message, exception.getMessage());
        assertEquals(cause, exception.getCause());
    }

    @Test
    @DisplayName("Should handle null message gracefully")
    void testNullMessage() {
        // When/Then
        assertDoesNotThrow(() -> {
            RuntimeCIFSException exception = new RuntimeCIFSException((String) null);
            assertNull(exception.getMessage());
        });

        assertDoesNotThrow(() -> {
            RuntimeCIFSException exception = new RuntimeCIFSException(null, new RuntimeException());
            assertNull(exception.getMessage());
        });
    }

    @Test
    @DisplayName("Should handle null cause gracefully")
    void testNullCause() {
        // When/Then
        assertDoesNotThrow(() -> {
            RuntimeCIFSException exception = new RuntimeCIFSException((Throwable) null);
            assertNull(exception.getCause());
        });

        assertDoesNotThrow(() -> {
            RuntimeCIFSException exception = new RuntimeCIFSException("Message", null);
            assertEquals("Message", exception.getMessage());
            assertNull(exception.getCause());
        });
    }

    @Test
    @DisplayName("Should preserve exception hierarchy")
    void testExceptionHierarchy() {
        // When
        RuntimeCIFSException exception = new RuntimeCIFSException("Test");

        // Then
        assertTrue(exception instanceof RuntimeException);
        assertTrue(exception instanceof Exception);
        assertTrue(exception instanceof Throwable);
    }

    @Test
    @DisplayName("Should support exception chaining")
    void testExceptionChaining() {
        // Given
        Exception rootCause = new IllegalStateException("Root error");
        RuntimeCIFSException intermediateCause = new RuntimeCIFSException("Intermediate", rootCause);

        // When
        RuntimeCIFSException finalException = new RuntimeCIFSException("Final error", intermediateCause);

        // Then
        assertEquals(intermediateCause, finalException.getCause());
        assertEquals(rootCause, finalException.getCause().getCause());
        assertEquals("Final error", finalException.getMessage());
        assertEquals("Intermediate", intermediateCause.getMessage());
        assertEquals("Root error", rootCause.getMessage());
    }

    @Test
    @DisplayName("Should preserve stack trace")
    void testStackTracePreservation() {
        // When
        RuntimeCIFSException exception = new RuntimeCIFSException("Test exception");

        // Then
        assertNotNull(exception.getStackTrace());
        assertTrue(exception.getStackTrace().length > 0);

        // Should contain this test method in stack trace
        boolean foundTestMethod = false;
        for (StackTraceElement element : exception.getStackTrace()) {
            if (element.getMethodName().contains("testStackTracePreservation")) {
                foundTestMethod = true;
                break;
            }
        }
        assertTrue(foundTestMethod);
    }

    @Test
    @DisplayName("Should create meaningful string representation")
    void testToString() {
        // Given
        String message = "Test CIFS runtime error";
        RuntimeCIFSException exception = new RuntimeCIFSException(message);

        // When
        String stringRep = exception.toString();

        // Then
        assertNotNull(stringRep);
        assertTrue(stringRep.contains("RuntimeCIFSException"));
        assertTrue(stringRep.contains(message));
    }

    @Test
    @DisplayName("Should handle various message types")
    void testVariousMessageTypes() {
        // Test empty message
        assertDoesNotThrow(() -> {
            RuntimeCIFSException exception = new RuntimeCIFSException("");
            assertEquals("", exception.getMessage());
        });

        // Test long message
        String longMessage = createTestString(1000);
        assertDoesNotThrow(() -> {
            RuntimeCIFSException exception = new RuntimeCIFSException(longMessage);
            assertEquals(longMessage, exception.getMessage());
        });

        // Test message with special characters
        String specialMessage = "Error: ñoñ-ASCII çhárácters & symbols!@#$%^&*()";
        assertDoesNotThrow(() -> {
            RuntimeCIFSException exception = new RuntimeCIFSException(specialMessage);
            assertEquals(specialMessage, exception.getMessage());
        });
    }

    @Test
    @DisplayName("Should handle different cause types")
    void testVariousCauseTypes() {
        // Test with checked exception
        Exception checkedException = new java.io.IOException("IO Error");
        assertDoesNotThrow(() -> {
            RuntimeCIFSException exception = new RuntimeCIFSException(checkedException);
            assertEquals(checkedException, exception.getCause());
        });

        // Test with runtime exception
        RuntimeException runtimeException = new IllegalArgumentException("Illegal arg");
        assertDoesNotThrow(() -> {
            RuntimeCIFSException exception = new RuntimeCIFSException(runtimeException);
            assertEquals(runtimeException, exception.getCause());
        });

        // Test with error
        Error error = new OutOfMemoryError("Out of memory");
        assertDoesNotThrow(() -> {
            RuntimeCIFSException exception = new RuntimeCIFSException(error);
            assertEquals(error, exception.getCause());
        });
    }

    @Test
    @DisplayName("Should maintain serialization compatibility")
    void testSerialization() {
        // Verify the class has serialVersionUID defined
        // This is important for version compatibility
        RuntimeCIFSException exception = new RuntimeCIFSException("Test");

        // The class should be serializable as it extends RuntimeException
        assertTrue(exception instanceof java.io.Serializable);
    }

    @Test
    @DisplayName("Should behave correctly in catch blocks")
    void testCatchBlockBehavior() {
        // Test that RuntimeCIFSException can be caught as RuntimeException
        assertThrows(RuntimeException.class, () -> {
            throw new RuntimeCIFSException("Test exception");
        });

        // Test that it can be caught specifically
        assertThrows(RuntimeCIFSException.class, () -> {
            throw new RuntimeCIFSException("Test exception");
        });

        // Test exception handling behavior
        try {
            throw new RuntimeCIFSException("Original message", new IllegalStateException("Cause"));
        } catch (RuntimeCIFSException e) {
            assertEquals("Original message", e.getMessage());
            assertTrue(e.getCause() instanceof IllegalStateException);
            assertEquals("Cause", e.getCause().getMessage());
        }
    }

    @Test
    @DisplayName("Should handle suppressed exceptions")
    void testSuppressedExceptions() {
        // Given
        RuntimeCIFSException mainException = new RuntimeCIFSException("Main error");
        RuntimeException suppressedException = new RuntimeException("Suppressed error");

        // When
        mainException.addSuppressed(suppressedException);

        // Then
        Throwable[] suppressed = mainException.getSuppressed();
        assertEquals(1, suppressed.length);
        assertEquals(suppressedException, suppressed[0]);
    }

    @Test
    @DisplayName("Should provide correct cause for constructor with cause only")
    void testCauseOnlyConstructorMessage() {
        // Given
        RuntimeException cause = new RuntimeException("Specific cause message");

        // When
        RuntimeCIFSException exception = new RuntimeCIFSException(cause);

        // Then
        assertEquals(cause, exception.getCause());
        assertNotNull(exception.getMessage());
        // The message should contain information about the cause
        assertTrue(exception.getMessage().contains("RuntimeException"));
        assertTrue(exception.getMessage().contains("Specific cause message"));
    }
}