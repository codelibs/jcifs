package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Test class for NtStatus constants
 */
@DisplayName("NtStatus Tests")
class NtStatusTest {

    @Test
    @DisplayName("Should define well-known NT status constants")
    void testWellKnownStatusConstants() {
        // Verify important NT status constants are defined
        assertEquals(0x00000000, NtStatus.NT_STATUS_SUCCESS);
        assertEquals((int) 0xC0000022L, NtStatus.NT_STATUS_ACCESS_DENIED);
        assertEquals((int) 0xC0000034L, NtStatus.NT_STATUS_OBJECT_NAME_NOT_FOUND);
        assertEquals((int) 0xC0000043L, NtStatus.NT_STATUS_SHARING_VIOLATION);
        assertEquals((int) 0xC000000DL, NtStatus.NT_STATUS_INVALID_PARAMETER);
    }

    @Test
    @DisplayName("Should identify success status")
    void testSuccessStatusIdentification() {
        // Given
        int successStatus = NtStatus.NT_STATUS_SUCCESS;

        // When/Then
        assertEquals(0x00000000, successStatus);
        // Success status should be zero
        assertTrue(successStatus == 0);
    }

    @Test
    @DisplayName("Should identify error status codes")
    void testErrorStatusIdentification() {
        // Given
        int[] errorStatuses =
                { NtStatus.NT_STATUS_ACCESS_DENIED, NtStatus.NT_STATUS_OBJECT_NAME_NOT_FOUND, NtStatus.NT_STATUS_SHARING_VIOLATION };

        // When/Then - All error codes should have high bit set (0xC prefix)
        for (int status : errorStatuses) {
            assertTrue((status & (int) 0xC0000000L) == (int) 0xC0000000L,
                    "Error status should have severity bits set to 0xC: " + Integer.toHexString(status));
        }
    }

    @Test
    @DisplayName("Should have status codes array")
    void testStatusCodesArray() {
        // When
        int[] codes = NtStatus.NT_STATUS_CODES;

        // Then
        assertNotNull(codes);
        assertTrue(codes.length > 0);
        // First code should be success
        assertEquals(NtStatus.NT_STATUS_SUCCESS, codes[0]);
    }

    @Test
    @DisplayName("Should have status messages array")
    void testStatusMessagesArray() {
        // When
        String[] messages = NtStatus.NT_STATUS_MESSAGES;

        // Then
        assertNotNull(messages);
        assertTrue(messages.length > 0);
        // Should have same length as codes array
        assertEquals(NtStatus.NT_STATUS_CODES.length, messages.length);

        // First message should be for success
        assertNotNull(messages[0]);
        assertTrue(messages[0].toLowerCase().contains("success") || messages[0].toLowerCase().contains("completed"));
    }

    @Test
    @DisplayName("Should handle access denied status")
    void testAccessDeniedStatus() {
        // Given
        int status = NtStatus.NT_STATUS_ACCESS_DENIED;

        // When/Then
        assertEquals((int) 0xC0000022L, status);
        // Should be an error status (0xC prefix)
        assertTrue((status & (int) 0xC0000000L) == (int) 0xC0000000L);
    }

    @Test
    @DisplayName("Should handle file not found status")
    void testFileNotFoundStatus() {
        // Given
        int status = NtStatus.NT_STATUS_OBJECT_NAME_NOT_FOUND;

        // When/Then
        assertEquals((int) 0xC0000034L, status);
        // Should be an error status (0xC prefix)
        assertTrue((status & (int) 0xC0000000L) == (int) 0xC0000000L);
    }

    @Test
    @DisplayName("Should handle sharing violation status")
    void testSharingViolationStatus() {
        // Given
        int status = NtStatus.NT_STATUS_SHARING_VIOLATION;

        // When/Then
        assertEquals((int) 0xC0000043L, status);
        // Should be an error status (0xC prefix)
        assertTrue((status & (int) 0xC0000000L) == (int) 0xC0000000L);
    }

    @Test
    @DisplayName("Should handle authentication failure status")
    void testAuthenticationFailureStatus() {
        // Given
        int status = NtStatus.NT_STATUS_LOGON_FAILURE;

        // When/Then
        assertEquals((int) 0xC000006DL, status);
        // Should be an error status (0xC prefix)
        assertTrue((status & (int) 0xC0000000L) == (int) 0xC0000000L);
    }

    @Test
    @DisplayName("Should handle informational status codes")
    void testInformationalStatusCodes() {
        // Given
        int infoStatus = NtStatus.NT_STATUS_BUFFER_OVERFLOW;

        // When/Then
        assertEquals((int) 0x80000005L, infoStatus);
        // Should be an informational/warning status (0x8 prefix)
        assertTrue((infoStatus & (int) 0x80000000L) == (int) 0x80000000L);
    }

    @Test
    @DisplayName("Should handle pending status")
    void testPendingStatus() {
        // Given
        int pendingStatus = NtStatus.NT_STATUS_PENDING;

        // When/Then
        assertEquals((int) 0x00000103L, pendingStatus);
        // Pending status is informational (not error)
        assertTrue((pendingStatus & (int) 0xC0000000L) != (int) 0xC0000000L);
    }

    @Test
    @DisplayName("Should define all expected constants")
    void testAllExpectedConstants() {
        // Verify important constants exist
        assertTrue(NtStatus.NT_STATUS_SUCCESS == 0x00000000);
        assertTrue(NtStatus.NT_STATUS_ACCESS_DENIED != 0);
        assertTrue(NtStatus.NT_STATUS_OBJECT_NAME_NOT_FOUND != 0);
        assertTrue(NtStatus.NT_STATUS_SHARING_VIOLATION != 0);
        assertTrue(NtStatus.NT_STATUS_INVALID_PARAMETER != 0);
        assertTrue(NtStatus.NT_STATUS_LOGON_FAILURE != 0);
        assertTrue(NtStatus.NT_STATUS_INSUFFICIENT_RESOURCES != 0);
    }
}