package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for the Trans2QueryPathInformation class.
 */
class Trans2QueryPathInformationTest {

    /**
     * Tests the constructor of Trans2QueryPathInformation.
     */
    @Test
    void testConstructor() {
        // Given
        String filename = "testFile.txt";
        int informationLevel = 0x0100; // SMB_QUERY_FILE_BASIC_INFO

        // When
        Trans2QueryPathInformation trans = new Trans2QueryPathInformation(filename, informationLevel);

        // Then
        assertEquals(filename, trans.path, "The path should be set correctly.");
        assertEquals(ServerMessageBlock.SMB_COM_TRANSACTION2, trans.command, "The command should be SMB_COM_TRANSACTION2.");
        assertEquals(SmbComTransaction.TRANS2_QUERY_PATH_INFORMATION, trans.subCommand,
                "The subCommand should be TRANS2_QUERY_PATH_INFORMATION.");
        assertEquals(0, trans.totalDataCount, "The totalDataCount should be 0.");
        assertEquals(2, trans.maxParameterCount, "The maxParameterCount should be 2.");
        assertEquals(40, trans.maxDataCount, "The maxDataCount should be 40.");
        assertEquals((byte) 0x00, trans.maxSetupCount, "The maxSetupCount should be 0.");
    }

    /**
     * Tests the writeSetupWireFormat method.
     */
    @Test
    void testWriteSetupWireFormat() {
        // Given
        Trans2QueryPathInformation trans = new Trans2QueryPathInformation("test.txt", 0x0101);
        byte[] dst = new byte[2];

        // When
        int bytesWritten = trans.writeSetupWireFormat(dst, 0);

        // Then
        assertEquals(2, bytesWritten, "Should write 2 bytes.");
        assertEquals(SmbComTransaction.TRANS2_QUERY_PATH_INFORMATION, dst[0], "The first byte should be the subCommand.");
        assertEquals((byte) 0x00, dst[1], "The second byte should be 0.");
    }

    /**
     * Tests the writeParametersWireFormat method.
     */
    @Test
    void testWriteParametersWireFormat() {
        // Given
        String filename = "a\\test\\path.txt";
        int informationLevel = 0x0102;
        Trans2QueryPathInformation trans = new Trans2QueryPathInformation(filename, informationLevel);
        // Expected size: 2 (info level) + 4 (reserved) + filename length + 1 (null terminator)
        byte[] dst = new byte[2 + 4 + filename.length() + 1];

        // When
        int bytesWritten = trans.writeParametersWireFormat(dst, 0);

        // Then
        assertEquals(dst.length, bytesWritten, "The number of bytes written should match the expected length.");
        // Check informationLevel
        assertEquals((byte) (informationLevel & 0xFF), dst[0]);
        assertEquals((byte) ((informationLevel >> 8) & 0xFF), dst[1]);
        // Check reserved bytes
        for (int i = 2; i < 6; i++) {
            assertEquals((byte) 0x00, dst[i], "Reserved byte at index " + i + " should be 0.");
        }
        // Check filename
        byte[] filenameBytes = filename.getBytes();
        for (int i = 0; i < filenameBytes.length; i++) {
            assertEquals(filenameBytes[i], dst[6 + i], "Filename byte at index " + i + " should match.");
        }
        // Check null terminator
        assertEquals((byte) 0x00, dst[dst.length - 1], "The last byte should be a null terminator.");
    }

    /**
     * Tests the writeDataWireFormat method.
     */
    @Test
    void testWriteDataWireFormat() {
        // Given
        Trans2QueryPathInformation trans = new Trans2QueryPathInformation("anyfile.txt", 0);
        byte[] dst = new byte[10];

        // When
        int bytesWritten = trans.writeDataWireFormat(dst, 0);

        // Then
        assertEquals(0, bytesWritten, "Should write 0 bytes.");
    }

    /**
     * Tests the readSetupWireFormat method.
     */
    @Test
    void testReadSetupWireFormat() {
        // Given
        Trans2QueryPathInformation trans = new Trans2QueryPathInformation("anyfile.txt", 0);
        byte[] buffer = new byte[10];

        // When
        int bytesRead = trans.readSetupWireFormat(buffer, 0, 10);

        // Then
        assertEquals(0, bytesRead, "Should read 0 bytes.");
    }

    /**
     * Tests the readParametersWireFormat method.
     */
    @Test
    void testReadParametersWireFormat() {
        // Given
        Trans2QueryPathInformation trans = new Trans2QueryPathInformation("anyfile.txt", 0);
        byte[] buffer = new byte[10];

        // When
        int bytesRead = trans.readParametersWireFormat(buffer, 0, 10);

        // Then
        assertEquals(0, bytesRead, "Should read 0 bytes.");
    }

    /**
     * Tests the readDataWireFormat method.
     */
    @Test
    void testReadDataWireFormat() {
        // Given
        Trans2QueryPathInformation trans = new Trans2QueryPathInformation("anyfile.txt", 0);
        byte[] buffer = new byte[10];

        // When
        int bytesRead = trans.readDataWireFormat(buffer, 0, 10);

        // Then
        assertEquals(0, bytesRead, "Should read 0 bytes.");
    }

    /**
     * Tests the toString method.
     */
    @Test
    void testToString() {
        // Given
        String filename = "test.txt";
        int informationLevel = 257; // 0x0101
        Trans2QueryPathInformation trans = new Trans2QueryPathInformation(filename, informationLevel);

        // When
        String result = trans.toString();

        // Then
        assertTrue(result.startsWith("Trans2QueryPathInformation["), "String should start with the class name.");
        assertTrue(result.contains("informationLevel=0x101"), "String should contain the correct information level.");
        assertTrue(result.contains("filename=test.txt"), "String should contain the correct filename.");
        assertTrue(result.endsWith("]"), "String should end with a closing bracket.");
    }
}
