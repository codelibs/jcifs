package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests for SmbAuthException covering all constructors and inherited behavior.
 */
@ExtendWith(MockitoExtension.class)
public class SmbAuthExceptionTest {

    /**
     * Provide representative error codes for the int constructor.
     * - NT status code (high bits set)
     * - Success code (0)
     * - Non-NT small code to exercise default mapping to NT_STATUS_UNSUCCESSFUL
     */
    static Stream<Arguments> intErrorCodes() {
        return Stream.of(Arguments.of(NtStatus.NT_STATUS_ACCESS_DENIED, NtStatus.NT_STATUS_ACCESS_DENIED),
                Arguments.of(NtStatus.NT_STATUS_SUCCESS, NtStatus.NT_STATUS_SUCCESS),
                Arguments.of(0x00001234, NtStatus.NT_STATUS_UNSUCCESSFUL));
    }

    @ParameterizedTest
    @MethodSource("intErrorCodes")
    @DisplayName("int ctor: sets message and NT status as expected")
    void intConstructor_populatesMessageAndStatus(int errCode, int expectedStatus) {
        // Arrange & Act: create exception with error code
        SmbAuthException ex = new SmbAuthException(errCode);

        // Assert: type, message derived from code, status mapping, and no cause
        assertNotNull(ex);
        assertTrue(ex instanceof SmbException);
        assertEquals(SmbException.getMessageByCode(errCode), ex.getMessage(), "message should reflect error code mapping");
        assertEquals(expectedStatus, ex.getNtStatus(), "status should map based on code");
        assertNull(ex.getCause(), "cause must be null for int constructor");
        assertNull(ex.getRootCause(), "rootCause must be null for int constructor");
    }

    /**
     * Validate message-only constructor with both null and empty messages.
     */
    @ParameterizedTest
    @MethodSource("messageProvider")
    @DisplayName("String ctor: preserves message; default unsuccessful status")
    void messageConstructor_handlesNullAndEmpty(String msg) {
        // Act
        SmbAuthException ex = new SmbAuthException(msg);

        // Assert
        assertEquals(msg, ex.getMessage());
        assertEquals(NtStatus.NT_STATUS_UNSUCCESSFUL, ex.getNtStatus(), "default status must be unsuccessful");
        assertNull(ex.getCause());
        assertNull(ex.getRootCause());
    }

    static Stream<Arguments> messageProvider() {
        return Stream.of(Arguments.of((String) null), Arguments.of(""));
    }

    /**
     * Validate message+cause constructor and that no interaction with cause occurs during construction.
     */
    @Test
    @DisplayName("String+Throwable ctor: sets message, cause and unsuccessful status")
    void messageAndCauseConstructor_setsFields(@Mock Throwable mockCause) {
        // Arrange
        String msg = "auth failed";

        // Act
        SmbAuthException ex = new SmbAuthException(msg, mockCause);

        // Assert
        assertEquals(msg, ex.getMessage());
        assertSame(mockCause, ex.getCause());
        assertSame(mockCause, ex.getRootCause());
        assertEquals(NtStatus.NT_STATUS_UNSUCCESSFUL, ex.getNtStatus());

        // Verify: constructor should not have interacted with the cause
        Mockito.verifyNoInteractions(mockCause);
    }

    /**
     * Ensure toString includes the exception class name and message, providing a readable representation.
     */
    @Test
    @DisplayName("toString contains class name and message")
    void toString_containsClassAndMessage() {
        // Arrange
        String msg = "login denied";
        SmbAuthException ex = new SmbAuthException(msg);

        // Act
        String s = ex.toString();

        // Assert
        assertNotNull(s);
        assertTrue(s.contains(SmbAuthException.class.getName()));
        assertTrue(s.contains(msg));
    }
}
