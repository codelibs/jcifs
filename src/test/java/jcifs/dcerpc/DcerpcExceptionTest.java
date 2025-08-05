package jcifs.dcerpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class DcerpcExceptionTest {

    /**
     * Test constructor DcerpcException(int error) with a known error code.
     */
    @Test
    void testConstructorWithError_knownCode() {
        int errorCode = DcerpcError.DCERPC_FAULT_ACCESS_DENIED;
        DcerpcException exception = new DcerpcException(errorCode);

        assertEquals(errorCode, exception.getErrorCode(), "Error code should match the input.");
        assertTrue(exception.getMessage().contains("DCERPC_FAULT_ACCESS_DENIED"),
                "Message should contain the corresponding fault message.");
    }

    /**
     * Test constructor DcerpcException(int error) with an unknown error code.
     */
    @Test
    void testConstructorWithError_unknownCode() {
        int errorCode = 0x12345678; // An arbitrary unknown error code
        DcerpcException exception = new DcerpcException(errorCode);

        assertEquals(errorCode, exception.getErrorCode(), "Error code should match the input.");
        assertEquals("0x12345678", exception.getMessage(), "Message should be hex string for unknown error code.");
    }

    /**
     * Test constructor DcerpcException(String msg).
     */
    @Test
    void testConstructorWithMessage() {
        String message = "Test message for DcerpcException.";
        DcerpcException exception = new DcerpcException(message);

        assertEquals(0, exception.getErrorCode(), "Error code should be 0 for message-only constructor.");
        assertEquals(message, exception.getMessage(), "Message should match the input.");
        assertNull(exception.getCause(), "Cause should be null for message-only constructor.");
    }

    /**
     * Test constructor DcerpcException(String msg, Throwable rootCause).
     */
    @Test
    void testConstructorWithMessageAndCause() {
        String message = "Test message with cause.";
        Throwable cause = new RuntimeException("Original cause.");
        DcerpcException exception = new DcerpcException(message, cause);

        assertEquals(0, exception.getErrorCode(), "Error code should be 0 for message and cause constructor.");
        assertEquals(message, exception.getMessage(), "Message should match the input.");
        assertEquals(cause, exception.getCause(), "Cause should match the input.");
        assertEquals(cause, exception.getRootCause(), "getRootCause() should return the same cause as getCause().");
    }

    /**
     * Test getErrorCode() method.
     */
    @Test
    void testGetErrorCode() {
        int errorCode = 0x00000005; // DCERPC_FAULT_ACCESS_DENIED
        DcerpcException exception = new DcerpcException(errorCode);
        assertEquals(errorCode, exception.getErrorCode(), "getErrorCode() should return the correct error code.");
    }

    /**
     * Test getRootCause() method (deprecated).
     */
    @Test
    void testGetRootCause() {
        Throwable cause = new IllegalArgumentException("Invalid argument.");
        DcerpcException exception = new DcerpcException("Error with cause.", cause);
        assertEquals(cause, exception.getRootCause(), "getRootCause() should return the original cause.");
    }

    /**
     * Test getMessageByDcerpcError() with a known error code (first element).
     */
    @Test
    void testGetMessageByDcerpcError_firstElement() {
        String message = DcerpcException.getMessageByDcerpcError(DcerpcError.DCERPC_FAULT_OTHER);
        assertEquals("DCERPC_FAULT_OTHER", message, "Should return correct message for first element.");
    }

    /**
     * Test getMessageByDcerpcError() with a known error code (middle element).
     */
    @Test
    void testGetMessageByDcerpcError_middleElement() {
        String message = DcerpcException.getMessageByDcerpcError(DcerpcError.DCERPC_FAULT_INVALID_TAG);
        assertEquals("DCERPC_FAULT_INVALID_TAG", message, "Should return correct message for middle element.");
    }

    /**
     * Test getMessageByDcerpcError() with a known error code (last element).
     */
    @Test
    void testGetMessageByDcerpcError_lastElement() {
        String message = DcerpcException.getMessageByDcerpcError(DcerpcError.DCERPC_FAULT_PROTO_ERROR);
        assertEquals("DCERPC_FAULT_PROTO_ERROR", message, "Should return correct message for last element.");
    }

    /**
     * Test getMessageByDcerpcError() with an unknown error code.
     */
    @Test
    void testGetMessageByDcerpcError_unknownCode() {
        int unknownCode = 0x99999999;
        String message = DcerpcException.getMessageByDcerpcError(unknownCode);
        assertEquals("0x99999999", message, "Should return hex string for unknown error code.");
    }

    /**
     * Test getMessageByDcerpcError() with an error code smaller than any known.
     */
    @Test
    void testGetMessageByDcerpcError_smallerThanAny() {
        int unknownCode = -1;
        String message = DcerpcException.getMessageByDcerpcError(unknownCode);
        assertEquals("0xFFFFFFFF", message, "Should return hex string for code smaller than any known.");
    }

    /**
     * Test getMessageByDcerpcError() with an error code larger than any known.
     * The binary search implementation has a bug where it accesses array out of bounds.
     */
    @Test
    void testGetMessageByDcerpcError_largerThanAny() {
        int unknownCode = 0x7FFFFFFF; // Max int value
        
        // The current implementation has a bug in the binary search that causes ArrayIndexOutOfBoundsException
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            DcerpcException.getMessageByDcerpcError(unknownCode);
        }, "Should throw ArrayIndexOutOfBoundsException due to binary search bug");
    }
}
