package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.util.function.Supplier;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SmbUnsupportedOperationExceptionTest {

    // Provides a variety of messages including edge cases
    static Stream<String> messages() {
        return Stream.of("custom message", "", " ", "αβγ", "x".repeat(1000), null);
    }

    @Test
    @DisplayName("Default constructor sets the expected message and no cause")
    void defaultConstructor_setsExpectedMessage_andNoCause() {
        // Arrange & Act
        SmbUnsupportedOperationException ex = new SmbUnsupportedOperationException();

        // Assert
        assertEquals("Operation is not supported with the negotiated capabilities", ex.getMessage(),
                "Default message should match the class contract");
        assertNull(ex.getCause(), "No cause expected from default constructor");
        assertTrue(ex instanceof SmbException, "Should be an SmbException");

        // toString should include the class name and the message
        String ts = ex.toString();
        assertTrue(ts.contains("SmbUnsupportedOperationException"), "toString should contain class name");
        assertTrue(ts.contains(ex.getMessage()), "toString should contain the detail message");
    }

    @ParameterizedTest(name = "Message preserved: [{0}]")
    @MethodSource("messages")
    @DisplayName("Message constructor preserves provided messages, including null/edge cases")
    void messageConstructor_preservesMessage(String msg) {
        // Arrange & Act
        SmbUnsupportedOperationException ex = new SmbUnsupportedOperationException(msg);

        // Assert
        assertEquals(msg, ex.getMessage(), "Constructor should preserve the provided message (including null)");
        assertNull(ex.getCause(), "No cause expected when only message is provided");

        // toString behavior mirrors Throwable: includes message when not null
        String ts = ex.toString();
        assertTrue(ts.contains("SmbUnsupportedOperationException"), "toString should contain class name");
        if (msg != null) {
            assertTrue(ts.contains(msg), "toString should contain provided message");
        } else {
            assertFalse(ts.contains(":"), "toString should not contain ':' when message is null");
        }
    }

    @Test
    @DisplayName("assertThrows captures and exposes the default message")
    void assertThrows_capturesDefaultMessage() {
        // Act & Assert
        SmbUnsupportedOperationException ex = assertThrows(SmbUnsupportedOperationException.class, () -> {
            throw new SmbUnsupportedOperationException();
        });
        assertEquals("Operation is not supported with the negotiated capabilities", ex.getMessage());
    }

    @Test
    @DisplayName("Mockito: stubbed collaborator throws RuntimeException wrapper and interactions are verified")
    void mockInteraction_stubsThrow_andVerifiesInvocation() {
        // Arrange: Since SmbUnsupportedOperationException is a checked exception (extends IOException),
        // we need to use a method that can throw checked exceptions or wrap it in a RuntimeException
        @SuppressWarnings("unchecked")
        Supplier<String> supplier = mock(Supplier.class);
        when(supplier.get()).thenThrow(new RuntimeException(new SmbUnsupportedOperationException("boom")));

        // Act & Assert: the exception is propagated and interaction recorded once
        RuntimeException thrown = assertThrows(RuntimeException.class, supplier::get);
        assertInstanceOf(SmbUnsupportedOperationException.class, thrown.getCause());
        assertEquals("boom", thrown.getCause().getMessage());
        verify(supplier, times(1)).get();
        verifyNoMoreInteractions(supplier);
    }

    @Test
    @DisplayName("No collaborator interaction occurs if exception is thrown beforehand")
    void noInteraction_whenExceptionOccursBeforeCall() {
        // Arrange
        Runnable r = mock(Runnable.class);

        // Act: simulate control flow where the exception happens before any collaborator is used
        try {
            throw new SmbUnsupportedOperationException();
        } catch (SmbUnsupportedOperationException ignored) {
            // ignore
        }

        // Assert: collaborator was never used
        verify(r, never()).run();
        verifyNoMoreInteractions(r);
    }
}
