package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import java.util.Arrays;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class DosErrorTest {

    // Helper that performs a lookup over the constants exposed by DosError.
    // Returns -1 if the DOS code is not mapped.
    private static int findNtStatusOrMinusOne(int dosCode) {
        for (int[] pair : DosError.DOS_ERROR_CODES) {
            // each pair is [dosCode, ntStatus]
            if (pair != null && pair.length == 2 && pair[0] == dosCode) {
                return pair[1];
            }
        }
        return -1;
    }

    // Provide a handful of representative mappings present in the table.
    static Stream<Arguments> knownMappings() {
        return Stream.of(Arguments.of(0x00000000, 0x00000000), Arguments.of(0x00020001, 0xc000000f), Arguments.of(0x00050001, 0xc0000022),
                Arguments.of(0x00500001, 0xc0000035), Arguments.of(0x007b0001, 0xc0000033), Arguments.of(0x00320001, 0xC00000BB));
    }

    @ParameterizedTest
    @MethodSource("knownMappings")
    @DisplayName("Happy path: known DOS codes map to expected NTSTATUS")
    void mapsKnownDosCodesToNtStatus(int dosCode, int expectedNtStatus) {
        // Act
        int actual = findNtStatusOrMinusOne(dosCode);

        // Assert
        assertEquals(expectedNtStatus, actual, "Mapping must match table entry");
    }

    @Test
    @DisplayName("Edge: zero DOS code maps to zero NTSTATUS")
    void zeroCodeMapsToZero() {
        // Act
        int actual = findNtStatusOrMinusOne(0x00000000);

        // Assert
        assertEquals(0x00000000, actual);
    }

    @ParameterizedTest
    @ValueSource(ints = { -1, 1, 0x00FFFF00, 0x0BADF00D })
    @DisplayName("Invalid or unknown DOS codes return not-found sentinel (-1)")
    void unknownCodesReturnMinusOne(int dosCode) {
        // Act
        int actual = findNtStatusOrMinusOne(dosCode);

        // Assert
        assertEquals(-1, actual);
    }

    @Test
    @DisplayName("Structure: DOS_ERROR_CODES is non-null with [code,status] pairs")
    void dosErrorCodesStructureIsValid() {
        // Arrange & Act
        int[][] table = DosError.DOS_ERROR_CODES;

        // Assert
        assertNotNull(table, "DOS_ERROR_CODES must not be null");
        assertTrue(table.length > 0, "DOS_ERROR_CODES must not be empty");
        for (int i = 0; i < table.length; i++) {
            int[] pair = table[i];
            assertNotNull(pair, "row " + i + " must not be null");
            assertEquals(2, pair.length, "row " + i + " must be [dos, ntstatus]");
        }
    }

    @Test
    @DisplayName("Messages: array is present and contains expected first entries")
    void dosErrorMessagesContainsExpectedTexts() {
        // Arrange & Act
        String[] msgs = DosError.DOS_ERROR_MESSAGES;

        // Assert
        assertNotNull(msgs);
        assertTrue(msgs.length >= 3, "Expect at least the first 3 entries present");
        assertEquals("The operation completed successfully.", msgs[0]);
        assertEquals("Incorrect function.", msgs[1]);
        assertEquals("Incorrect function.", msgs[2]);
    }

    @Test
    @DisplayName("Messages: accessing invalid index throws ArrayIndexOutOfBoundsException")
    void messagesOutOfBoundsThrows() {
        // Arrange
        String[] msgs = DosError.DOS_ERROR_MESSAGES;

        // Act & Assert: negative index
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            @SuppressWarnings("unused")
            String s = msgs[-1];
        });

        // Act & Assert: index equal to length
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            @SuppressWarnings("unused")
            String s = msgs[msgs.length];
        });
    }

    @Test
    @DisplayName("Interaction: consumer is invoked for each found mapping")
    void interactionWithConsumerIsAsExpected() {
        // Arrange: choose a small set of known DOS codes
        List<Integer> inputs = Arrays.asList(0x00000000, 0x00050001, 0x007b0001, 0x0BADF00D);
        @SuppressWarnings("unchecked")
        BiConsumer<Integer, Integer> consumer = mock(BiConsumer.class);

        // Act: for each input, if a mapping exists, notify the consumer
        for (int dos : inputs) {
            int nt = findNtStatusOrMinusOne(dos);
            if (nt != -1) {
                consumer.accept(dos, nt);
            }
        }

        // Assert: consumer called exactly for the 3 known codes, with the right arguments
        ArgumentCaptor<Integer> dosCaptor = ArgumentCaptor.forClass(Integer.class);
        ArgumentCaptor<Integer> ntCaptor = ArgumentCaptor.forClass(Integer.class);
        verify(consumer, times(3)).accept(dosCaptor.capture(), ntCaptor.capture());
        assertIterableEquals(Arrays.asList(0x00000000, 0x00050001, 0x007b0001), dosCaptor.getAllValues());
        assertIterableEquals(Arrays.asList(0x00000000, 0xc0000022, 0xc0000033), ntCaptor.getAllValues());

        // And ensure no further interactions happened
        verifyNoMoreInteractions(consumer);
    }
}
