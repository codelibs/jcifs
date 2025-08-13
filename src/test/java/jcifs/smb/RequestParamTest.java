package jcifs.smb;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.ThrowingSupplier;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link RequestParam} covering enum mechanics and edge cases.
 */
@ExtendWith(MockitoExtension.class)
public class RequestParamTest {

    // Happy path: values() returns all constants in declaration order
    @Test
    @DisplayName("values() returns all declared constants in order")
    void valuesContainsAllInOrder() {
        RequestParam[] values = RequestParam.values();

        assertNotNull(values, "values() must not return null");
        assertEquals(4, values.length, "There must be exactly 4 constants");
        assertArrayEquals(
            new RequestParam[] {
                RequestParam.NONE,
                RequestParam.NO_TIMEOUT,
                RequestParam.NO_RETRY,
                RequestParam.RETAIN_PAYLOAD
            },
            values,
            "values() order should match declaration order"
        );
    }

    // Happy path: valueOf resolves each constant name; toString equals name; ordinal is stable
    @ParameterizedTest
    @ValueSource(strings = {"NONE", "NO_TIMEOUT", "NO_RETRY", "RETAIN_PAYLOAD"})
    @DisplayName("valueOf(name) returns the correct enum and toString matches name")
    void valueOfResolvesNamesAndToString(String name) {
        RequestParam rp = RequestParam.valueOf(name);
        assertNotNull(rp);
        assertEquals(name, rp.name(), "name() must match input");
        assertEquals(name, rp.toString(), "toString() should default to name()");
        // Ordinal is consistent with declaration order
        switch (name) {
            case "NONE":
                assertEquals(0, rp.ordinal());
                break;
            case "NO_TIMEOUT":
                assertEquals(1, rp.ordinal());
                break;
            case "NO_RETRY":
                assertEquals(2, rp.ordinal());
                break;
            case "RETAIN_PAYLOAD":
                assertEquals(3, rp.ordinal());
                break;
            default:
                fail("Unexpected name under test: " + name);
        }
    }

    // Edge: valueOf is case-sensitive and does not accept unknown identifiers
    @ParameterizedTest
    @ValueSource(strings = {"none", "No_Retry", "retain_payload", "UNKNOWN", "NO-RETRY"})
    @DisplayName("valueOf with unknown or differently-cased names throws IllegalArgumentException")
    void valueOfRejectsUnknownOrCaseMismatch(String badName) {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> RequestParam.valueOf(badName));
        assertTrue(ex.getMessage().contains(badName), "Exception message should mention the bad name");
    }

    // Edge/Invalid: empty string is invalid for valueOf
    @ParameterizedTest
    @EmptySource
    @DisplayName("valueOf(\"\") throws IllegalArgumentException for empty input")
    void valueOfRejectsEmpty(String empty) {
        assertThrows(IllegalArgumentException.class, () -> RequestParam.valueOf(empty));
    }

    // Invalid: null is not allowed for valueOf
    @ParameterizedTest
    @NullSource
    @DisplayName("valueOf(null) throws NullPointerException")
    void valueOfRejectsNull(String input) {
        assertThrows(NullPointerException.class, () -> RequestParam.valueOf(input));
    }

    // Sanity: Enum.valueOf(Class, String) behaves identically to RequestParam.valueOf(String)
    @Test
    @DisplayName("Enum.valueOf mirrors RequestParam.valueOf for valid names")
    void enumValueOfParity() {
        for (RequestParam rp : RequestParam.values()) {
            assertSame(rp, Enum.valueOf(RequestParam.class, rp.name()));
        }
    }

    // Interaction: Demonstrate no external interactions occur (no collaborators to call)
    // We use Mockito in a minimal, meaningful way: pass the enum to a mocked consumer and verify interaction.
    interface EnumConsumer { void accept(RequestParam rp); }

    @Mock
    EnumConsumer consumer;

    @Test
    @DisplayName("Enum value can be passed to collaborators without side effects")
    void enumUsedWithCollaboratorHasNoSideEffects() {
        // Arrange: pick a value and a mocked consumer
        RequestParam rp = RequestParam.NO_RETRY;

        // Act: pass to the collaborator
        consumer.accept(rp);

        // Assert: interaction happened exactly once with correct argument; no other calls
        verify(consumer, times(1)).accept(RequestParam.NO_RETRY);
        verifyNoMoreInteractions(consumer);
    }
}

