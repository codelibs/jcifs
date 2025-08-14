package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Test class for SmbComTreeDisconnect.
 */
class SmbComTreeDisconnectTest {

    /**
     * Test the constructor of SmbComTreeDisconnect.
     */
    @Test
    void testConstructor() {
        // When
        SmbComTreeDisconnect smbComTreeDisconnect = new SmbComTreeDisconnect();

        // Then
        assertEquals(ServerMessageBlock.SMB_COM_TREE_DISCONNECT, smbComTreeDisconnect.command, "Command should be SMB_COM_TREE_DISCONNECT");
    }

    /**
     * Test the writeParameterWordsWireFormat method.
     */
    @Test
    void testWriteParameterWordsWireFormat() {
        // Given
        SmbComTreeDisconnect smbComTreeDisconnect = new SmbComTreeDisconnect();
        byte[] dst = new byte[10];

        // When
        int result = smbComTreeDisconnect.writeParameterWordsWireFormat(dst, 0);

        // Then
        assertEquals(0, result, "writeParameterWordsWireFormat should return 0");
    }

    /**
     * Test the writeBytesWireFormat method.
     */
    @Test
    void testWriteBytesWireFormat() {
        // Given
        SmbComTreeDisconnect smbComTreeDisconnect = new SmbComTreeDisconnect();
        byte[] dst = new byte[10];

        // When
        int result = smbComTreeDisconnect.writeBytesWireFormat(dst, 0);

        // Then
        assertEquals(0, result, "writeBytesWireFormat should return 0");
    }

    /**
     * Test the readParameterWordsWireFormat method.
     */
    @Test
    void testReadParameterWordsWireFormat() {
        // Given
        SmbComTreeDisconnect smbComTreeDisconnect = new SmbComTreeDisconnect();
        byte[] buffer = new byte[10];

        // When
        int result = smbComTreeDisconnect.readParameterWordsWireFormat(buffer, 0);

        // Then
        assertEquals(0, result, "readParameterWordsWireFormat should return 0");
    }

    /**
     * Test the readBytesWireFormat method.
     */
    @Test
    void testReadBytesWireFormat() {
        // Given
        SmbComTreeDisconnect smbComTreeDisconnect = new SmbComTreeDisconnect();
        byte[] buffer = new byte[10];

        // When
        int result = smbComTreeDisconnect.readBytesWireFormat(buffer, 0);

        // Then
        assertEquals(0, result, "readBytesWireFormat should return 0");
    }

    /**
     * Test the toString method.
     */
    @Test
    void testToString() {
        // Given
        SmbComTreeDisconnect smbComTreeDisconnect = new SmbComTreeDisconnect();

        // When
        String result = smbComTreeDisconnect.toString();

        // Then
        assertTrue(result.startsWith("SmbComTreeDisconnect["), "toString should start with 'SmbComTreeDisconnect['");
        assertTrue(result.endsWith("]"), "toString should end with ']'");
    }
}
