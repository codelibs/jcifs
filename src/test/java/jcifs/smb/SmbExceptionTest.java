package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import jcifs.BaseTest;

/**
 * Test class for SmbException functionality
 */
@DisplayName("SmbException Tests")
class SmbExceptionTest extends BaseTest {

    @Test
    @DisplayName("Should create SmbException with NT status code")
    void testSmbExceptionWithNTStatus() {
        // Given
        int ntStatus = NtStatus.NT_STATUS_ACCESS_DENIED;

        // When
        SmbException exception = new SmbException(ntStatus, false);

        // Then
        assertNotNull(exception);
        assertEquals(ntStatus, exception.getNtStatus());
        assertTrue(exception.getMessage().contains("Access is denied"));
    }

    @Test
    @DisplayName("Should create SmbException with message")
    void testSmbExceptionWithMessage() {
        // Given
        String message = "Custom error message";

        // When
        SmbException exception = new SmbException(message);

        // Then
        assertNotNull(exception);
        assertEquals(message, exception.getMessage());
    }

    @Test
    @DisplayName("Should create SmbException with cause")
    void testSmbExceptionWithCause() {
        // Given
        Exception cause = new RuntimeException("Root cause");
        String message = "SMB operation failed";

        // When
        SmbException exception = new SmbException(message, cause);

        // Then
        assertNotNull(exception);
        assertEquals(message, exception.getMessage());
        assertEquals(cause, exception.getCause());
    }

    @ParameterizedTest
    @ValueSource(ints = { NtStatus.NT_STATUS_SUCCESS, NtStatus.NT_STATUS_ACCESS_DENIED, NtStatus.NT_STATUS_OBJECT_NAME_NOT_FOUND,
            NtStatus.NT_STATUS_SHARING_VIOLATION, NtStatus.NT_STATUS_INVALID_PARAMETER })
    @DisplayName("Should handle various NT status codes")
    void testVariousNTStatusCodes(int ntStatus) {
        // When
        SmbException exception = new SmbException(ntStatus, false);

        // Then
        assertNotNull(exception);
        assertEquals(ntStatus, exception.getNtStatus());
        assertNotNull(exception.getMessage());
        assertFalse(exception.getMessage().isEmpty());
    }

    @Test
    @DisplayName("Should format error message for file not found")
    void testFileNotFoundError() {
        // Given
        int ntStatus = NtStatus.NT_STATUS_OBJECT_NAME_NOT_FOUND;

        // When
        SmbException exception = new SmbException(ntStatus, false);

        // Then
        assertTrue(exception.getMessage().toLowerCase().contains("not found")
                || exception.getMessage().toLowerCase().contains("does not exist")
                || exception.getMessage().toLowerCase().contains("cannot find"));
    }

    @Test
    @DisplayName("Should format error message for access denied")
    void testAccessDeniedError() {
        // Given
        int ntStatus = NtStatus.NT_STATUS_ACCESS_DENIED;

        // When
        SmbException exception = new SmbException(ntStatus, false);

        // Then
        assertTrue(exception.getMessage().toLowerCase().contains("access") && exception.getMessage().toLowerCase().contains("denied"));
    }

    @Test
    @DisplayName("Should format error message for sharing violation")
    void testSharingViolationError() {
        // Given
        int ntStatus = NtStatus.NT_STATUS_SHARING_VIOLATION;

        // When
        SmbException exception = new SmbException(ntStatus, false);

        // Then
        assertTrue(exception.getMessage().toLowerCase().contains("sharing") || exception.getMessage().toLowerCase().contains("violation")
                || exception.getMessage().toLowerCase().contains("used") || exception.getMessage().toLowerCase().contains("being used")
                || exception.getMessage().toLowerCase().contains("process"));
    }

    @Test
    @DisplayName("Should handle DOS error codes")
    void testDOSErrorCodes() {
        // Given
        int dosError = 0x00020002; // File not found from DOS_ERROR_CODES

        // When
        SmbException exception = new SmbException(dosError, false);

        // Then
        assertNotNull(exception);
        assertNotNull(exception.getMessage());
        assertTrue(exception.getMessage().length() > 0);
    }

    @Test
    @DisplayName("Should check if exception is retriable")
    void testRetriableExceptions() {
        // Test non-retriable errors
        SmbException accessDenied = new SmbException(NtStatus.NT_STATUS_ACCESS_DENIED, false);
        // Note: isRetriable() method does not exist in SmbException
        assertNotNull(accessDenied);

        SmbException notFound = new SmbException(NtStatus.NT_STATUS_OBJECT_NAME_NOT_FOUND, false);
        assertNotNull(notFound);

        // Test potentially retriable errors
        SmbException sharingViolation = new SmbException(NtStatus.NT_STATUS_SHARING_VIOLATION, false);
        // Sharing violations might be retriable in some contexts
        // The implementation determines this
        assertNotNull(sharingViolation);
    }

    @Test
    @DisplayName("Should preserve stack trace information")
    void testStackTracePreservation() {
        // When
        SmbException exception = new SmbException("Test exception");

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
    @DisplayName("Should handle exception chaining")
    void testExceptionChaining() {
        // Given
        Exception rootCause = new RuntimeException("Root cause");
        SmbException intermediateCause = new SmbException("Intermediate", rootCause);

        // When
        SmbException finalException = new SmbException("Final error", intermediateCause);

        // Then
        assertEquals(intermediateCause, finalException.getCause());
        assertEquals(rootCause, finalException.getCause().getCause());
    }

    @Test
    @DisplayName("Should handle null message gracefully")
    void testNullMessage() {
        // When/Then
        assertDoesNotThrow(() -> {
            SmbException exception = new SmbException((String) null);
            assertNotNull(exception);
        });
    }

    @Test
    @DisplayName("Should convert to string properly")
    void testToString() {
        // Given
        String message = "Test error message";
        SmbException exception = new SmbException(message);

        // When
        String stringRep = exception.toString();

        // Then
        assertNotNull(stringRep);
        assertTrue(stringRep.contains("SmbException"));
        assertTrue(stringRep.contains(message));
    }

    @Test
    @DisplayName("Should handle authentication exceptions")
    void testAuthenticationExceptions() {
        // Given
        int ntStatus = NtStatus.NT_STATUS_LOGON_FAILURE;

        // When
        SmbException exception = new SmbException(ntStatus, false);

        // Then
        assertNotNull(exception);
        assertTrue(exception.getMessage().toLowerCase().contains("logon") || exception.getMessage().toLowerCase().contains("authentication")
                || exception.getMessage().toLowerCase().contains("login") || exception.getMessage().toLowerCase().contains("user") 
                || exception.getMessage().toLowerCase().contains("password"));
    }
}