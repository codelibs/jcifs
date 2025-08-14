package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class WinErrorTest {

    // Helper to lookup a message by code using the production arrays
    private static Optional<String> lookupMessage(int code) {
        int[] codes = WinError.WINERR_CODES;
        String[] msgs = WinError.WINERR_MESSAGES;
        for (int i = 0; i < codes.length; i++) {
            if (codes[i] == code) {
                return Optional.of(msgs[i]);
            }
        }
        return Optional.empty();
    }

    // Producer for code->message pairs covering all known constants (happy path)
    static Stream<Arguments> knownCodeMessagePairs() {
        return Stream.of(Arguments.of(WinError.ERROR_SUCCESS, "The operation completed successfully."),
                Arguments.of(WinError.ERROR_ACCESS_DENIED, "Access is denied."),
                Arguments.of(WinError.ERROR_REQ_NOT_ACCEP,
                        "No more connections can be made to this remote computer at this time because there are already as many connections as the computer can accept."),
                Arguments.of(WinError.ERROR_BAD_PIPE, "The pipe state is invalid."),
                Arguments.of(WinError.ERROR_PIPE_BUSY, "All pipe instances are busy."),
                Arguments.of(WinError.ERROR_NO_DATA, "The pipe is being closed."),
                Arguments.of(WinError.ERROR_PIPE_NOT_CONNECTED, "No process is on the other end of the pipe."),
                Arguments.of(WinError.ERROR_MORE_DATA, "More data is available."),
                Arguments.of(WinError.ERROR_SERVICE_NOT_INSTALLED, "The service is not available"), Arguments
                        .of(WinError.ERROR_NO_BROWSER_SERVERS_FOUND, "The list of servers for this workgroup is not currently available."));
    }

    @Test
    @DisplayName("Constants: values match Windows error codes")
    void constants_have_expected_values() {
        // Ensure each public constant has its documented numeric value (happy path)
        assertAll(() -> assertEquals(0, WinError.ERROR_SUCCESS), () -> assertEquals(5, WinError.ERROR_ACCESS_DENIED),
                () -> assertEquals(71, WinError.ERROR_REQ_NOT_ACCEP), () -> assertEquals(230, WinError.ERROR_BAD_PIPE),
                () -> assertEquals(231, WinError.ERROR_PIPE_BUSY), () -> assertEquals(232, WinError.ERROR_NO_DATA),
                () -> assertEquals(233, WinError.ERROR_PIPE_NOT_CONNECTED), () -> assertEquals(234, WinError.ERROR_MORE_DATA),
                () -> assertEquals(2184, WinError.ERROR_SERVICE_NOT_INSTALLED),
                () -> assertEquals(6118, WinError.ERROR_NO_BROWSER_SERVERS_FOUND));
    }

    @Test
    @DisplayName("Arrays: non-null, same length, and exact contents")
    void arrays_are_well_formed_and_match() {
        // Validate arrays existence and alignment (edge and structure checks)
        assertNotNull(WinError.WINERR_CODES, "WINERR_CODES should not be null");
        assertNotNull(WinError.WINERR_MESSAGES, "WINERR_MESSAGES should not be null");
        assertEquals(WinError.WINERR_CODES.length, WinError.WINERR_MESSAGES.length, "Codes/messages length mismatch");

        // Exact content check to guard against accidental reordering or drift
        assertArrayEquals(
                new int[] { WinError.ERROR_SUCCESS, WinError.ERROR_ACCESS_DENIED, WinError.ERROR_REQ_NOT_ACCEP, WinError.ERROR_BAD_PIPE,
                        WinError.ERROR_PIPE_BUSY, WinError.ERROR_NO_DATA, WinError.ERROR_PIPE_NOT_CONNECTED, WinError.ERROR_MORE_DATA,
                        WinError.ERROR_SERVICE_NOT_INSTALLED, WinError.ERROR_NO_BROWSER_SERVERS_FOUND },
                WinError.WINERR_CODES, "WINERR_CODES content differs");

        assertArrayEquals(new String[] { "The operation completed successfully.", "Access is denied.",
                "No more connections can be made to this remote computer at this time because there are already as many connections as the computer can accept.",
                "The pipe state is invalid.", "All pipe instances are busy.", "The pipe is being closed.",
                "No process is on the other end of the pipe.", "More data is available.", "The service is not available",
                "The list of servers for this workgroup is not currently available." }, WinError.WINERR_MESSAGES,
                "WINERR_MESSAGES content differs");
    }

    @ParameterizedTest(name = "Known code {0} maps to message")
    @MethodSource("knownCodeMessagePairs")
    void lookup_returns_expected_message_for_known_codes(int code, String expectedMessage) {
        // Valid inputs: each known code must map to its documented message
        assertEquals(expectedMessage, lookupMessage(code).orElse(null));
    }

    @ParameterizedTest
    @ValueSource(ints = { -1, Integer.MIN_VALUE, Integer.MAX_VALUE })
    @DisplayName("Unknown codes: lookup returns empty Optional")
    void lookup_returns_empty_for_unknown_codes(int unknownCode) {
        // Invalid inputs: codes not present should yield no message
        // Guard to ensure test remains valid if constants change in future
        for (int c : WinError.WINERR_CODES) {
            assertNotEquals(unknownCode, c, "Chosen unknown code unexpectedly clashes with a known code");
        }
        assertTrue(lookupMessage(unknownCode).isEmpty());
    }

    @Test
    @DisplayName("Codes: all non-negative and unique")
    void codes_are_non_negative_and_unique() {
        // Edge checks: ensure there are no negative or duplicate codes
        Set<Integer> seen = new HashSet<>();
        for (int c : WinError.WINERR_CODES) {
            assertTrue(c >= 0, "Code should be non-negative: " + c);
            assertTrue(seen.add(c), "Duplicate code detected: " + c);
        }
    }

    // Simple collaborator to demonstrate interaction verification with Mockito
    interface Handler {
        void handle(int code, String message);
    }

    @Mock
    Handler handler;

    @Test
    @DisplayName("Interaction: handler called with each code/message pair")
    void interaction_with_mock_handler_is_as_expected() {
        // Interaction test: simulate passing each code/message to a collaborator
        for (int i = 0; i < WinError.WINERR_CODES.length; i++) {
            handler.handle(WinError.WINERR_CODES[i], WinError.WINERR_MESSAGES[i]);
        }

        // Verify the collaborator is invoked exactly N times
        verify(handler, times(WinError.WINERR_CODES.length)).handle(anyInt(), anyString());

        // Capture one known interaction to verify argument integrity
        ArgumentCaptor<Integer> codeCap = ArgumentCaptor.forClass(Integer.class);
        ArgumentCaptor<String> msgCap = ArgumentCaptor.forClass(String.class);
        verify(handler, atLeastOnce()).handle(codeCap.capture(), msgCap.capture());

        // Assert at least one captured pair is a known mapping (happy path spot check)
        assertTrue(codeCap.getAllValues().contains(WinError.ERROR_ACCESS_DENIED));
        int idx = codeCap.getAllValues().indexOf(WinError.ERROR_ACCESS_DENIED);
        assertEquals("Access is denied.", msgCap.getAllValues().get(idx));

        // Ensure no unexpected empty messages (edge: empty strings)
        msgCap.getAllValues().forEach(m -> assertNotNull(m));
        msgCap.getAllValues().forEach(m -> assertFalse(m.trim().isEmpty(), "Message should not be empty"));
    }
}
