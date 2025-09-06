package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import java.lang.reflect.Field;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SMBSignatureValidationExceptionTest {

    // Happy path: default constructor creates an exception with no message/cause
    @Test
    @DisplayName("Default ctor: null message/cause and success status")
    void defaultConstructor_hasNullMessageAndCause_andDefaultStatus() {
        // Arrange & Act
        SMBSignatureValidationException ex = new SMBSignatureValidationException();

        // Assert
        assertNull(ex.getMessage(), "Default ctor should not set a message");
        assertNull(ex.getCause(), "Default ctor should not set a cause");
        assertTrue(ex instanceof SmbException, "Should be an SmbSystemException subtype");
        // SmbSystemException default ctor leaves status 0, which equals NT_STATUS_SUCCESS
        assertEquals(NtStatus.NT_STATUS_SUCCESS, ex.getNtStatus(), "Default status should be success (0)");
    }

    // Edge/null/empty: message-only constructor should propagate message and set unsuccessful status
    @ParameterizedTest
    @NullSource
    @ValueSource(strings = { "", " ", "simple", "with unicode Ω≈ç√", "long-0123456789-abcdefghijklmnopqrstuvwxyz" })
    @DisplayName("Message-only ctor: propagates message and unsuccessful status")
    void messageOnlyConstructor_setsMessage_andUnsuccessfulStatus(String msg) {
        // Arrange & Act
        SMBSignatureValidationException ex = new SMBSignatureValidationException(msg);

        // Assert
        if (msg == null) {
            assertNull(ex.getMessage(), "Null message should remain null");
        } else {
            assertEquals(msg, ex.getMessage(), "Message should be stored as provided");
        }
        assertNull(ex.getCause(), "Cause should be null for message-only ctor");
        assertEquals(NtStatus.NT_STATUS_UNSUCCESSFUL, ex.getNtStatus(), "Status should default to unsuccessful for message ctor");
    }

    // Happy path: message + cause constructor should chain cause and set unsuccessful status
    @ParameterizedTest
    @NullSource
    @ValueSource(strings = { "", "error", "detailed message" })
    @DisplayName("Message+Cause ctor: propagates message/cause and unsuccessful status")
    void messageAndCauseConstructor_setsMessageCause_andUnsuccessfulStatus(String msg) {
        // Arrange
        Throwable cause = new IllegalStateException("root cause");

        // Act
        SMBSignatureValidationException ex = new SMBSignatureValidationException(msg, cause);

        // Assert
        if (msg == null) {
            assertNull(ex.getMessage(), "Null message should remain null");
        } else {
            assertEquals(msg, ex.getMessage(), "Message should be stored as provided");
        }
        assertSame(cause, ex.getCause(), "Cause should be stored and retrievable");
        assertSame(cause, ex.getRootCause(), "Deprecated getRootCause should match getCause");
        assertEquals(NtStatus.NT_STATUS_UNSUCCESSFUL, ex.getNtStatus(), "Status should default to unsuccessful for message+cause ctor");
    }

    // Interaction: passing a mocked cause should not trigger interactions (nothing to call)
    @Test
    @DisplayName("Mocked cause: no interactions occur when stored as cause")
    void mockedCause_isStored_withoutInteraction() {
        // Arrange
        Throwable mocked = mock(Throwable.class);

        // Act
        SMBSignatureValidationException ex = new SMBSignatureValidationException("msg", mocked);

        // Assert
        assertSame(mocked, ex.getCause(), "Mocked cause should be preserved");
        verifyNoInteractions(mocked);
    }

    // Reflection-based check: ensure serialVersionUID remains the declared constant
    @Test
    @DisplayName("serialVersionUID matches declared constant")
    void serialVersionUID_hasExpectedValue() throws Exception {
        // Arrange
        Field f = SMBSignatureValidationException.class.getDeclaredField("serialVersionUID");
        f.setAccessible(true);

        // Act
        long value = (long) f.get(null);

        // Assert
        assertEquals(2283323396289696982L, value, "serialVersionUID should be stable");
    }

    // Behavior check: toString contains class name and message when present
    @Test
    @DisplayName("toString contains class name and message when provided")
    void toString_containsClassName_and_Message() {
        // Arrange
        String msg = "signature invalid";
        SMBSignatureValidationException ex = new SMBSignatureValidationException(msg);

        // Act
        String s = ex.toString();

        // Assert
        assertTrue(s.contains("SMBSignatureValidationException"), "toString should include class name");
        assertTrue(s.contains(msg), "toString should include message when provided");
    }
}
