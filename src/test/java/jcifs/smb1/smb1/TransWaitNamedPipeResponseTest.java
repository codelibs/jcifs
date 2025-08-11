package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests for {@link TransWaitNamedPipeResponse}.
 *
 * The implementation contains only trivial methods that return {@code 0}
 * or construct a string representation.  The tests focus on:
 *
 * <ul>
 *   <li>happy‑path behaviour</li>
 *   <li>boundary arguments (e.g., negative indices, large values)</li>
 *   <li>string representation containing the class name</li>
 *   <li>null buffer handling</li>
 * </ul>
 */
final class TransWaitNamedPipeResponseTest {

    /**
     * Verify that the default constructor creates an instance.
     */
    @Test
    void constructorInitialisesInstance() {
        // Arrange & Act
        TransWaitNamedPipeResponse resp = new TransWaitNamedPipeResponse();
        // Assert
        assertNotNull(resp, "Instance should not be null");
    }

    /**
     * All wire‑format methods should return zero regardless of inputs.
     */
    @Nested
    @DisplayName("Wire format method behaviour")
    class WireFormatMethods {
        @ParameterizedTest
        @ValueSource(ints = {0, 1, -1, Integer.MAX_VALUE, Integer.MIN_VALUE})
        @DisplayName("writeSetupWireFormat returns 0 for all indices")
        void writeSetupWireFormatReturnsZero(int index) {
            TransWaitNamedPipeResponse resp = new TransWaitNamedPipeResponse();
            assertEquals(0, resp.writeSetupWireFormat(new byte[10], index),
                "writeSetupWireFormat should always return 0");
        }

        @ParameterizedTest
        @ValueSource(ints = {0, 5, -5, Integer.MAX_VALUE})
        @DisplayName("writeParametersWireFormat returns 0 for all indices")
        void writeParametersWireFormatReturnsZero(int index) {
            TransWaitNamedPipeResponse resp = new TransWaitNamedPipeResponse();
            assertEquals(0, resp.writeParametersWireFormat(new byte[10], index),
                "writeParametersWireFormat should always return 0");
        }

        @ParameterizedTest
        @ValueSource(ints = {0, 2, -2, Integer.MAX_VALUE})
        @DisplayName("writeDataWireFormat returns 0 for all indices")
        void writeDataWireFormatReturnsZero(int index) {
            TransWaitNamedPipeResponse resp = new TransWaitNamedPipeResponse();
            assertEquals(0, resp.writeDataWireFormat(new byte[10], index),
                "writeDataWireFormat should always return 0");
        }

        @ParameterizedTest
        @ValueSource(ints = {0, 2, -2, Integer.MAX_VALUE})
        @DisplayName("readSetupWireFormat returns 0 regardless of buffer and length")
        void readSetupWireFormatReturnsZero(int len) {
            TransWaitNamedPipeResponse resp = new TransWaitNamedPipeResponse();
            assertEquals(0, resp.readSetupWireFormat(new byte[10], 0, len),
                "readSetupWireFormat should always return 0");
        }

        @ParameterizedTest
        @ValueSource(ints = {0, 3, -3, Integer.MAX_VALUE})
        @DisplayName("readParametersWireFormat returns 0 regardless of buffer and length")
        void readParametersWireFormatReturnsZero(int len) {
            TransWaitNamedPipeResponse resp = new TransWaitNamedPipeResponse();
            assertEquals(0, resp.readParametersWireFormat(new byte[10], 0, len),
                "readParametersWireFormat should always return 0");
        }

        @ParameterizedTest
        @ValueSource(ints = {0, 4, -4, Integer.MAX_VALUE})
        @DisplayName("readDataWireFormat returns 0 regardless of buffer and length")
        void readDataWireFormatReturnsZero(int len) {
            TransWaitNamedPipeResponse resp = new TransWaitNamedPipeResponse();
            assertEquals(0, resp.readDataWireFormat(new byte[10], 0, len),
                "readDataWireFormat should always return 0");
        }
    }

    /**
     * The {@code toString} method should include the class name and the
     * representation of the superclass.
     */
    @Test
    void toStringIncludesClassName() {
        TransWaitNamedPipeResponse resp = new TransWaitNamedPipeResponse();
        String str = resp.toString();
        assertNotNull(str, "toString should not return null");
        assertTrue(str.startsWith("TransWaitNamedPipeResponse["),
            "toString should begin with class name");
    }

    /**
     * Verify that all methods can be called with null buffers without 
     * throwing exceptions. This test ensures robustness of the implementation.
     */
    @Test
    void methodsHandleNullBuffersGracefully() {
        // Arrange
        TransWaitNamedPipeResponse resp = new TransWaitNamedPipeResponse();
        // Act & Assert - no exceptions should be thrown
        assertDoesNotThrow(() -> resp.writeSetupWireFormat(null, 0));
        assertDoesNotThrow(() -> resp.writeParametersWireFormat(null, 0));
        assertDoesNotThrow(() -> resp.writeDataWireFormat(null, 0));
        assertDoesNotThrow(() -> resp.readSetupWireFormat(null, 0, 0));
        assertDoesNotThrow(() -> resp.readParametersWireFormat(null, 0, 0));
        assertDoesNotThrow(() -> resp.readDataWireFormat(null, 0, 0));
        assertDoesNotThrow(() -> resp.toString());
    }
}

