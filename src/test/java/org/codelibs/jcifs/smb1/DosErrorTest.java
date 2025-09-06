package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.util.Arrays;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link DosError}.  Since {@link DosError} only contains
 * constants, the tests exercise the data and small helper logic in this
 * test class.
 */
public class DosErrorTest {
    private static Optional<Integer> findNtStatus(int dosErrorCode) {
        return Arrays.stream(DosError.DOS_ERROR_CODES).filter(pair -> pair[0] == dosErrorCode).map(pair -> pair[1]).findFirst();
    }

    @Test
    @DisplayName("DOS_ERROR_CODES is non‑null and non‑empty")
    void testCodesArrayExistence() {
        assertNotNull(DosError.DOS_ERROR_CODES, "DOS_ERROR_CODES should be non‑null");
        assertTrue(DosError.DOS_ERROR_CODES.length > 0, "DOS_ERROR_CODES should contain at least one mapping");
    }

    @Test
    @DisplayName("Each error code mapping contains exactly two ints")
    void testEachPairLength() {
        for (int i = 0; i < DosError.DOS_ERROR_CODES.length; i++) {
            int[] pair = DosError.DOS_ERROR_CODES[i];
            assertEquals(2, pair.length, String.format("Error mapping at index %d should contain two integers", i));
        }
    }

    @Test
    @DisplayName("Known DOS error is correctly mapped to NTSTATUS")
    void testKnownMapping() {
        final int dosErr = 0x00010001;
        final int expectedNt = 0xc0000002;
        Optional<Integer> actual = findNtStatus(dosErr);
        assertTrue(actual.isPresent(), String.format("Mapping for %08x should exist", dosErr));
        assertEquals(expectedNt, actual.get(), String.format("NTSTATUS for %08x should be %08x", dosErr, expectedNt));
    }

    @Test
    @DisplayName("Unknown DOS error code yields empty Optional")
    void testUnknownCode() {
        Optional<Integer> noMatch = findNtStatus(0xdeadbeef);
        assertFalse(noMatch.isPresent(), "Mapping for unknown code should be absent");
    }

    @Test
    @DisplayName("Mocked consumer receives correct NTSTATUS value")
    void testConsumerInteraction() {
        final int dosErr = 0x00010001;
        final int expectedNt = 0xc0000002;

        interface NtStatusConsumer {
            void consume(int ntStatus);
        }
        NtStatusConsumer mock = mock(NtStatusConsumer.class);
        findNtStatus(dosErr).ifPresent(mock::consume);
        verify(mock).consume(expectedNt);
    }

    @Test
    @DisplayName("DOS_ERROR_MESSAGES length matches expectations")
    void testMessageArrayLength() {
        assertNotNull(DosError.DOS_ERROR_MESSAGES, "DOS_ERROR_MESSAGES should be non‑null");
        assertTrue(DosError.DOS_ERROR_MESSAGES.length >= DosError.DOS_ERROR_CODES.length, "DOS_ERROR_MESSAGES should cover all codes");
    }
}
