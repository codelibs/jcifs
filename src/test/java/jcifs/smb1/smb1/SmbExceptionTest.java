package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

import java.io.IOException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@link SmbException}.
 *
 * The tests exercise the public API: constructors, {@link #getNtStatus()},
 * {@link #getRootCause()}, and {@link #toString()}.
 */
@ExtendWith(MockitoExtension.class)
class SmbExceptionTest {

    /**
     * Happy path – constructor with a valid NT status code (0).
     */
    @Test
    @DisplayName("Constructor 0 – NT_STATUS_SUCCESS")
    void testConstructorWithZeroCode() {
        SmbException ex = new SmbException(0, false);
        assertEquals("NT_STATUS_SUCCESS", ex.getMessage());
        assertEquals(0, ex.getNtStatus());
        assertNull(ex.getRootCause(), "root cause should be null for this ctor");
        assertEquals("jcifs.smb1.smb1.SmbException: NT_STATUS_SUCCESS", ex.toString());
    }

    /**
     * Edge case – constructor using the winerr flag.
     */
    @Test
    @DisplayName("Winerr code 123 – message equals 123")
    void testConstructorWithWinerr() {
        SmbException ex = new SmbException(123, true);
        assertEquals("123", ex.getMessage());
        assertEquals(123, ex.getNtStatus());
    }

    /**
     * Parameterised test covering many error codes. For 0 the status is 0;
     * all other codes (which are not mapped) resolve to {@code NT_STATUS_UNSUCCESSFUL}.
     */
    @ParameterizedTest
    @ValueSource(integers = {0, 1, 123, -7})
    void testGetNtStatusVariousCodes(int errcode) {
        SmbException ex = new SmbException(errcode, false);
        int expected = (errcode == 0) ? 0 : NtStatus.NT_STATUS_UNSUCCESSFUL;
        assertEquals(expected, ex.getNtStatus(),
                "Status should match mapping or fallback");
    }

    /**
     * Verify that root causes are stored and returned correctly.
     */
    @Test
    @DisplayName("Root cause propagation")
    void testRootCausePropagation() {
        Throwable root = mock(Throwable.class);
        SmbException ex = new SmbException(0, root);
        assertSame(root, ex.getRootCause());
    }

    /**
     * Verify that the string-ctor sets status to {@code NT_STATUS_UNSUCCESSFUL}.
     */
    @Test
    @DisplayName("String constructor sets NT_STATUS_UNSUCCESSFUL status")
    void testStringConstructor() {
        SmbException ex = new SmbException("custom message");
        assertEquals("custom message", ex.getMessage());
        assertEquals(NtStatus.NT_STATUS_UNSUCCESSFUL, ex.getNtStatus());
    }

    /**
     * Verify that the message + rootCause constructor stores the root.
     */
    @Test
    @DisplayName("Message + root cause stores root cause")
    void testStringAndThrowableConstructor() {
        Throwable root = mock(Throwable.class);
        SmbException ex = new SmbException("oops", root);
        assertSame(root, ex.getRootCause());
    }

    /**
     * Verify that {@link #toString()} includes a stack trace when a root cause
     * is present.
     */
    @Test
    @DisplayName("toString with root cause contains stack trace")
    void testToStringWithRootCause() {
        RuntimeException cause = new RuntimeException("boom");
        SmbException ex = new SmbException(0, cause);
        assertTrue(ex.toString().contains("RuntimeException"),
                "String representation must include the root cause stack trace");
    }

    /**
     * Verify that {@link #toString()} with no root cause equals the default
     * {@code IOException#toString()}.
     */
    @Test
    @DisplayName("toString without root cause matches IOException#toString")
    void testToStringWithoutRootCause() {
        SmbException ex = new SmbException(0, false);
        assertEquals("jcifs.smb1.smb1.SmbException: NT_STATUS_SUCCESS", ex.toString());
    }
}

