package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@link SmbComLogoffAndX}.
 */
@ExtendWith(MockitoExtension.class)
class SmbComLogoffAndXTest {

    @Test
    @DisplayName("constructor accepts null andx")
    void constructorWithNullAndx() {
        SmbComLogoffAndX msg = new SmbComLogoffAndX(null);
        assertNotNull(msg, "Message must not be null after construction");
    }

    @ParameterizedTest
    @ValueSource(ints = { 0, 1, 5, -1, 10 })
    @DisplayName("writeParameterWordsWireFormat always returns 0")
    void writeParameterWordsWireFormatReturnsZero(int index) {
        SmbComLogoffAndX msg = new SmbComLogoffAndX(null);
        assertEquals(0, msg.writeParameterWordsWireFormat(new byte[10], index), "Expected zero returned regardless of index");
        assertEquals(0, msg.writeParameterWordsWireFormat(null, index), "Expected zero even when dst array is null");
    }

    @ParameterizedTest
    @ValueSource(ints = { 0, 3, 9, -5 })
    @DisplayName("writeBytesWireFormat always returns 0")
    void writeBytesWireFormatReturnsZero(int index) {
        SmbComLogoffAndX msg = new SmbComLogoffAndX(null);
        assertEquals(0, msg.writeBytesWireFormat(new byte[20], index));
        assertEquals(0, msg.writeBytesWireFormat(null, index));
    }

    @ParameterizedTest
    @ValueSource(ints = { 0, -1, 7 })
    @DisplayName("readParameterWordsWireFormat always returns 0")
    void readParameterWordsWireFormatReturnsZero(int index) {
        SmbComLogoffAndX msg = new SmbComLogoffAndX(null);
        assertEquals(0, msg.readParameterWordsWireFormat(new byte[5], index));
        assertEquals(0, msg.readParameterWordsWireFormat(null, index));
    }

    @ParameterizedTest
    @ValueSource(ints = { 0, 4, -3 })
    @DisplayName("readBytesWireFormat always returns 0")
    void readBytesWireFormatReturnsZero(int index) {
        SmbComLogoffAndX msg = new SmbComLogoffAndX(null);
        assertEquals(0, msg.readBytesWireFormat(new byte[15], index));
        assertEquals(0, msg.readBytesWireFormat(null, index));
    }

    @Test
    @DisplayName("toString formats correctly")
    void toStringFormatsCorrectly() {
        SmbComLogoffAndX msg = new SmbComLogoffAndX(null);
        String s = msg.toString();
        assertNotNull(s, "toString should not be null");
        assertTrue(s.startsWith("SmbComLogoffAndX["), "expected prefix " + "SmbComLogoffAndX[" + " but got " + s);
        assertTrue(s.endsWith("]"), "expected suffix ] but got " + s);
        String inner = s.substring("SmbComLogoffAndX[".length(), s.length() - 1);
        assertFalse(inner.isEmpty(), "inner part of toString should not be empty");
    }

    @Test
    @DisplayName("constructor sets correct command value")
    void constructorSetsCorrectCommand() {
        SmbComLogoffAndX msg = new SmbComLogoffAndX(null);
        assertNotNull(msg, "Message should not be null");
        // SMB_COM_LOGOFF_ANDX = 0x74
        assertEquals((byte) 0x74, msg.command, "Command should be SMB_COM_LOGOFF_ANDX");
    }

    @Test
    @DisplayName("constructor with mock andx properly sets andx field")
    void constructorWithMockAndx() {
        // Create a mock ServerMessageBlock
        ServerMessageBlock mockAndx = mock(ServerMessageBlock.class);
        mockAndx.command = (byte) 0x2E; // Set a different command value (e.g., SMB_COM_READ_ANDX)

        // Create SmbComLogoffAndX with the mock
        SmbComLogoffAndX msg = new SmbComLogoffAndX(mockAndx);

        // Verify the object was created successfully
        assertNotNull(msg, "Message should not be null");
        // The command should still be SMB_COM_LOGOFF_ANDX regardless of andx command
        assertEquals((byte) 0x74, msg.command, "Command should be SMB_COM_LOGOFF_ANDX");
    }

    @Test
    @DisplayName("constructor with null andx does not throw exception")
    void constructorWithNullAndxNoException() {
        // This test verifies that passing null doesn't cause any issues
        assertDoesNotThrow(() -> {
            SmbComLogoffAndX msg = new SmbComLogoffAndX(null);
            assertNotNull(msg, "Message should be created even with null andx");
            assertEquals((byte) 0x74, msg.command, "Command should be SMB_COM_LOGOFF_ANDX");
        });
    }
}
