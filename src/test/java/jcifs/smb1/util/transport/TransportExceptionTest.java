package jcifs.smb1.util.transport;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for TransportException class
 */
public class TransportExceptionTest {

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create exception with no arguments")
        void testDefaultConstructor() {
            TransportException exception = new TransportException();

            assertNotNull(exception);
            assertNull(exception.getMessage());
            assertNull(exception.getRootCause());
            assertTrue(exception instanceof IOException);
        }

        @Test
        @DisplayName("Should create exception with message")
        void testConstructorWithMessage() {
            String message = "Test error message";
            TransportException exception = new TransportException(message);

            assertNotNull(exception);
            assertEquals(message, exception.getMessage());
            assertNull(exception.getRootCause());
        }

        @Test
        @DisplayName("Should create exception with root cause")
        void testConstructorWithRootCause() {
            Exception rootCause = new IllegalArgumentException("Root cause exception");
            TransportException exception = new TransportException(rootCause);

            assertNotNull(exception);
            assertNull(exception.getMessage());
            assertEquals(rootCause, exception.getRootCause());
        }

        @Test
        @DisplayName("Should create exception with message and root cause")
        void testConstructorWithMessageAndRootCause() {
            String message = "Test error message";
            Exception rootCause = new IllegalArgumentException("Root cause exception");
            TransportException exception = new TransportException(message, rootCause);

            assertNotNull(exception);
            assertEquals(message, exception.getMessage());
            assertEquals(rootCause, exception.getRootCause());
        }

        @Test
        @DisplayName("Should handle null root cause")
        void testConstructorWithNullRootCause() {
            TransportException exception = new TransportException((Throwable) null);

            assertNotNull(exception);
            assertNull(exception.getRootCause());
        }

        @Test
        @DisplayName("Should handle null message with root cause")
        void testConstructorWithNullMessageAndRootCause() {
            Exception rootCause = new RuntimeException("Root cause");
            TransportException exception = new TransportException(null, rootCause);

            assertNotNull(exception);
            assertNull(exception.getMessage());
            assertEquals(rootCause, exception.getRootCause());
        }
    }

    @Nested
    @DisplayName("GetRootCause Tests")
    class GetRootCauseTests {

        @Test
        @DisplayName("Should return root cause when set")
        void testGetRootCause() {
            Exception rootCause = new IllegalStateException("Test root cause");
            TransportException exception = new TransportException("Message", rootCause);

            assertEquals(rootCause, exception.getRootCause());
        }

        @Test
        @DisplayName("Should return null when no root cause")
        void testGetRootCauseWhenNull() {
            TransportException exception = new TransportException("Message");

            assertNull(exception.getRootCause());
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should return simple string when no root cause")
        void testToStringWithoutRootCause() {
            String message = "Test exception message";
            TransportException exception = new TransportException(message);

            String result = exception.toString();

            assertNotNull(result);
            assertTrue(result.contains("TransportException"));
            assertTrue(result.contains(message));
            assertFalse(result.contains("\n"));
        }

        @Test
        @DisplayName("Should include stack trace when root cause exists")
        void testToStringWithRootCause() {
            String message = "Transport error";
            String rootMessage = "Root cause error";
            Exception rootCause = new IllegalArgumentException(rootMessage);
            TransportException exception = new TransportException(message, rootCause);

            String result = exception.toString();

            assertNotNull(result);
            assertTrue(result.contains("TransportException"));
            assertTrue(result.contains(message));
            assertTrue(result.contains("\n"));
            assertTrue(result.contains("IllegalArgumentException"));
            assertTrue(result.contains(rootMessage));
            assertTrue(result.contains("at ")); // Stack trace indicator
        }

        @Test
        @DisplayName("Should handle root cause without message")
        void testToStringWithRootCauseNoMessage() {
            Exception rootCause = new NullPointerException();
            TransportException exception = new TransportException(rootCause);

            String result = exception.toString();

            assertNotNull(result);
            assertTrue(result.contains("TransportException"));
            assertTrue(result.contains("NullPointerException"));
            assertTrue(result.contains("\n"));
        }

        @Test
        @DisplayName("Should handle deeply nested exceptions")
        void testToStringWithNestedExceptions() {
            Exception innermost = new IOException("Innermost exception");
            Exception middle = new RuntimeException("Middle exception", innermost);
            Exception rootCause = new IllegalStateException("Outer exception", middle);
            TransportException exception = new TransportException("Transport failed", rootCause);

            String result = exception.toString();

            assertNotNull(result);
            assertTrue(result.contains("Transport failed"));
            assertTrue(result.contains("IllegalStateException"));
            assertTrue(result.contains("Outer exception"));
            // The nested exceptions will appear in the stack trace
            assertTrue(result.contains("Caused by"));
        }

        @Test
        @DisplayName("Should handle exception with empty message")
        void testToStringWithEmptyMessage() {
            TransportException exception = new TransportException("");

            String result = exception.toString();

            assertNotNull(result);
            assertTrue(result.contains("TransportException"));
        }
    }

    @Nested
    @DisplayName("IOException Compatibility Tests")
    class IOExceptionCompatibilityTests {

        @Test
        @DisplayName("Should be assignable to IOException")
        void testIsIOException() {
            TransportException exception = new TransportException("Test");

            assertTrue(exception instanceof IOException);

            // Should be able to assign to IOException variable
            IOException ioException = exception;
            assertNotNull(ioException);
        }

        @Test
        @DisplayName("Should work in catch blocks for IOException")
        void testCatchAsIOException() {
            assertDoesNotThrow(() -> {
                try {
                    throw new TransportException("Test exception");
                } catch (IOException e) {
                    // Should catch TransportException as IOException
                    assertTrue(e instanceof TransportException);
                }
            });
        }

        @Test
        @DisplayName("Should preserve IOException behavior")
        void testIOExceptionBehavior() {
            String message = "IO operation failed";
            TransportException exception = new TransportException(message);

            // Test standard IOException methods
            assertEquals(message, exception.getMessage());
            assertNotNull(exception.getStackTrace());
            assertTrue(exception.getStackTrace().length > 0);

            // Test that it can be thrown as IOException
            assertThrows(IOException.class, () -> {
                throw exception;
            });
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle very long messages")
        void testVeryLongMessage() {
            StringBuilder longMessage = new StringBuilder();
            for (int i = 0; i < 10000; i++) {
                longMessage.append("x");
            }
            String message = longMessage.toString();

            TransportException exception = new TransportException(message);

            assertEquals(message, exception.getMessage());
            assertTrue(exception.toString().contains("TransportException"));
        }

        @Test
        @DisplayName("Should handle special characters in message")
        void testSpecialCharactersInMessage() {
            String message = "Error: \n\t\r\\ \"special\" 'chars' @#$%^&*()";
            TransportException exception = new TransportException(message);

            assertEquals(message, exception.getMessage());
            assertNotNull(exception.toString());
        }

        @Test
        @DisplayName("Should handle circular reference in root cause")
        void testCircularReferenceInRootCause() {
            // Create a mock exception that could have circular reference
            Exception rootCause = mock(Exception.class);
            when(rootCause.getMessage()).thenReturn("Mocked exception");

            TransportException exception = new TransportException("Test", rootCause);

            assertEquals(rootCause, exception.getRootCause());
            // toString should not cause infinite loop
            assertDoesNotThrow(() -> exception.toString());
        }
    }

    @Nested
    @DisplayName("Serialization Tests")
    class SerializationTests {

        @Test
        @DisplayName("Should maintain exception hierarchy")
        void testExceptionHierarchy() {
            TransportException exception = new TransportException("Test");

            // Verify the exception hierarchy
            assertTrue(exception instanceof IOException);
            assertTrue(exception instanceof Exception);
            assertTrue(exception instanceof Throwable);
        }

        @Test
        @DisplayName("Should preserve message through exception chain")
        void testMessagePreservation() {
            String originalMessage = "Original error";
            TransportException original = new TransportException(originalMessage);

            // Wrap in another exception
            TransportException wrapper = new TransportException("Wrapper", original);

            assertEquals("Wrapper", wrapper.getMessage());
            assertEquals(original, wrapper.getRootCause());
            assertEquals(originalMessage, ((TransportException) wrapper.getRootCause()).getMessage());
        }
    }
}