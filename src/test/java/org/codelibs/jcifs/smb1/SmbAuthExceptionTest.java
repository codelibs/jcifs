package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Tests for {@link SmbAuthException}.
 *
 * These tests exercise the constructor and the mapping logic of
 * {@link SmbException#getMessageByCode(int)} and
 * {@link SmbException#getStatusByCode(int)}.
 */
@DisplayName("SmbAuthException Tests")
class SmbAuthExceptionTest {

    /**
     * Provides a set of error codes covering normal, edge and unknown cases.
     */
    static Stream<Arguments> errorCodes() {
        return Stream.of(
                // Known NT status code - NT_STATUS_UNSUCCESSFUL
                Arguments.of(0xC0000001, "A device attached to the system is not functioning."),
                Arguments.of(0x00000000, "NT_STATUS_SUCCESS"),
                // An error that maps via DOS mapping
                Arguments.of(0x00000002, SmbException.getMessageByCode(0x00000002)),
                // Unknown code → hex string (uppercase)
                Arguments.of(0xDEADBEEF, "0xDEADBEEF"));
    }

    @ParameterizedTest
    @MethodSource("errorCodes")
    void constructorInitialisesMessageAndStatus(int code, String expectedMsg) {
        SmbAuthException e = new SmbAuthException(code);
        assertEquals(expectedMsg, e.getMessage(), "message for code " + Integer.toHexString(code));
        assertEquals(SmbException.getStatusByCode(code), e.getNtStatus(), "status for code " + Integer.toHexString(code));
    }

    @Test
    void negativeCodeDefaultsToUnsuccessful() {
        SmbAuthException e = new SmbAuthException(-1);
        assertEquals(SmbException.getStatusByCode(-1), e.getNtStatus());
        assertEquals(SmbException.getMessageByCode(-1), e.getMessage());
    }

    @Test
    void zeroCodeProducesSuccess() {
        SmbAuthException e = new SmbAuthException(0);
        assertEquals("NT_STATUS_SUCCESS", e.getMessage());
        assertEquals(SmbException.getStatusByCode(0), e.getNtStatus());
    }
}
