package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

/**
 * Tests for {@link WinError} interface constants and static arrays.
 * The interface has no instance methods, so the tests focus on
 * value correctness and array integrity.  A tiny Mockito example
 * demonstrates that the interface can be mocked if another class
 * depends on it.
 */
public class WinErrorTest {

    @Nested
    @DisplayName("Constant value checks")
    class ConstantValues {
        @Test
        void successIsZero() {
            assertEquals(0, WinError.ERROR_SUCCESS, "ERROR_SUCCESS should be 0");
        }

        @Test
        void accessDeniedIsFive() {
            assertEquals(5, WinError.ERROR_ACCESS_DENIED, "ERROR_ACCESS_DENIED should be 5");
        }

        @Test
        void knownErrorCodes() {
            assertEquals(71, WinError.ERROR_REQ_NOT_ACCEP, "ERROR_REQ_NOT_ACCEP expected 71");
            assertEquals(230, WinError.ERROR_BAD_PIPE, "ERROR_BAD_PIPE expected 230");
            assertEquals(6118, WinError.ERROR_NO_BROWSER_SERVERS_FOUND, "ERROR_NO_BROWSER_SERVERS_FOUND expected 6118");
        }
    }

    @Nested
    @DisplayName("Array content checks")
    class ArrayChecks {
        @Test
        void arraysHaveSameLength() {
            assertEquals(WinError.WINERR_CODES.length, WinError.WINERR_MESSAGES.length,
                         "WINERR_CODES and WINERR_MESSAGES should have the same length");
        }

        @Test
        void messagesAlignWithCodes() {
            for (int i = 0; i < WinError.WINERR_CODES.length; i++) {
                int code = WinError.WINERR_CODES[i];
                String message = WinError.WINERR_MESSAGES[i];
                assertNotNull(message, String.format("Message for code %d should not be null", code));
            }
        }
    }

    @Nested
    @DisplayName("Boundary conditions")
    class Boundary {
        @Test
        void accessingInvalidIndexThrows() {
            assertThrows(ArrayIndexOutOfBoundsException.class,
                          () -> { int dummy = WinError.WINERR_CODES[WinError.WINERR_CODES.length]; });
        }
    }

    @Test
    @DisplayName("Mockito mock of WinError")
    void mockInterfaceNoOps() {
        WinError mock = Mockito.mock(WinError.class);
        assertNotNull(mock);
        assertTrue(Mockito.mockingDetails(mock).isMock(), "Object should be a Mockito mock");
        Mockito.verifyNoInteractions(mock);
    }
}

