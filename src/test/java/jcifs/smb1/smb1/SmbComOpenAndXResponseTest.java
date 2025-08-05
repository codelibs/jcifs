package jcifs.smb1.smb1;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for SmbComOpenAndXResponse.
 * This class tests the functionality of parsing the response of an SMB_COM_OPEN_ANDX command.
 */
class SmbComOpenAndXResponseTest {

    /**
     * Tests the readParameterWordsWireFormat method.
     * Verifies that the parameter words from a byte buffer are correctly read and assigned to the object's fields.
     */
    @Test
    void testReadParameterWordsWireFormat() {
        SmbComOpenAndXResponse response = new SmbComOpenAndXResponse();

        // Prepare a sample byte buffer representing the parameter words of an OpenAndX response.
        // Total 26 bytes of parameters.
        byte[] buffer = new byte[26];
        int bufferIndex = 0;

        // Expected values
        int expectedFid = 12345;
        int expectedFileAttributes = 0x20; // ARCHIVE
        long expectedLastWriteTime = 1672531200000L; // Corresponds to 2023-01-01 00:00:00 UTC
        int expectedDataSize = 4096;
        int expectedGrantedAccess = 0x0001; // FILE_READ_DATA
        int expectedFileType = 0x0002; // SMB_FILE_TYPE_DISK
        int expectedDeviceState = 0;
        int expectedAction = 0x0001; // FILE_WAS_OPENED
        int expectedServerFid = 54321;

        // Write values to buffer in little-endian format.
        writeInt2(buffer, bufferIndex, expectedFid); // fid
        bufferIndex += 2;
        writeInt2(buffer, bufferIndex, expectedFileAttributes); // fileAttributes
        bufferIndex += 2;
        // UTime is seconds since 1970-01-01 00:00:00 UTC
        writeUTime(buffer, bufferIndex, expectedLastWriteTime); // lastWriteTime
        bufferIndex += 4;
        writeInt4(buffer, bufferIndex, expectedDataSize); // dataSize
        bufferIndex += 4;
        writeInt2(buffer, bufferIndex, expectedGrantedAccess); // grantedAccess
        bufferIndex += 2;
        writeInt2(buffer, bufferIndex, expectedFileType); // fileType
        bufferIndex += 2;
        writeInt2(buffer, bufferIndex, expectedDeviceState); // deviceState
        bufferIndex += 2;
        writeInt2(buffer, bufferIndex, expectedAction); // action
        bufferIndex += 2;
        writeInt4(buffer, bufferIndex, expectedServerFid); // serverFid
        bufferIndex += 4;
        // 2 bytes reserved/padding
        buffer[bufferIndex++] = 0;
        buffer[bufferIndex++] = 0;


        // Call the method to be tested
        int bytesRead = response.readParameterWordsWireFormat(buffer, 0);

        // Assert that the number of bytes read is correct
        assertEquals(26, bytesRead, "The number of bytes read should be 26.");

        // Assert that all fields are correctly populated
        assertEquals(expectedFid, response.fid, "fid should be correctly parsed.");
        assertEquals(expectedFileAttributes, response.fileAttributes, "fileAttributes should be correctly parsed.");
        assertEquals(expectedLastWriteTime, response.lastWriteTime, "lastWriteTime should be correctly parsed.");
        assertEquals(expectedDataSize, response.dataSize, "dataSize should be correctly parsed.");
        assertEquals(expectedGrantedAccess, response.grantedAccess, "grantedAccess should be correctly parsed.");
        assertEquals(expectedFileType, response.fileType, "fileType should be correctly parsed.");
        assertEquals(expectedDeviceState, response.deviceState, "deviceState should be correctly parsed.");
        assertEquals(expectedAction, response.action, "action should be correctly parsed.");
        assertEquals(expectedServerFid, response.serverFid, "serverFid should be correctly parsed.");
    }

    /**
     * Tests the toString method.
     * Verifies that the toString method produces a string containing the key fields and their values.
     */
    @Test
    void testToString() {
        SmbComOpenAndXResponse response = new SmbComOpenAndXResponse();

        // Set values for the fields
        response.fid = 1;
        response.fileAttributes = 2;
        response.lastWriteTime = 1234567890L;
        response.dataSize = 1024;
        response.grantedAccess = 3;
        response.fileType = 4;
        response.deviceState = 5;
        response.action = 6;
        response.serverFid = 7;
        response.andxCommand = (byte) 0xFF; // No specific command
        response.andxOffset = 0;

        // Call the method to be tested
        String result = response.toString();

        // Assert that the output string contains the expected field values
        assertTrue(result.contains("fid=1"), "toString() should include fid.");
        assertTrue(result.contains("fileAttributes=2"), "toString() should include fileAttributes.");
        assertTrue(result.contains("lastWriteTime=1234567890"), "toString() should include lastWriteTime.");
        assertTrue(result.contains("dataSize=1024"), "toString() should include dataSize.");
        assertTrue(result.contains("grantedAccess=3"), "toString() should include grantedAccess.");
        assertTrue(result.contains("fileType=4"), "toString() should include fileType.");
        assertTrue(result.contains("deviceState=5"), "toString() should include deviceState.");
        assertTrue(result.contains("action=6"), "toString() should include action.");
        assertTrue(result.contains("serverFid=7"), "toString() should include serverFid.");
    }

    /**
     * Tests the writeParameterWordsWireFormat method.
     * This method currently does nothing and should return 0.
     */
    @Test
    void testWriteParameterWordsWireFormat() {
        SmbComOpenAndXResponse response = new SmbComOpenAndXResponse();
        byte[] dst = new byte[10];
        int bytesWritten = response.writeParameterWordsWireFormat(dst, 0);
        assertEquals(0, bytesWritten, "writeParameterWordsWireFormat should return 0 as it is not implemented.");
    }

    /**
     * Tests the writeBytesWireFormat method.
     * This method currently does nothing and should return 0.
     */
    @Test
    void testWriteBytesWireFormat() {
        SmbComOpenAndXResponse response = new SmbComOpenAndXResponse();
        byte[] dst = new byte[10];
        int bytesWritten = response.writeBytesWireFormat(dst, 0);
        assertEquals(0, bytesWritten, "writeBytesWireFormat should return 0 as it is not implemented.");
    }

    /**
     * Tests the readBytesWireFormat method.
     * This method currently does nothing and should return 0.
     */
    @Test
    void testReadBytesWireFormat() {
        SmbComOpenAndXResponse response = new SmbComOpenAndXResponse();
        byte[] buffer = new byte[10];
        int bytesRead = response.readBytesWireFormat(buffer, 0);
        assertEquals(0, bytesRead, "readBytesWireFormat should return 0 as it is not implemented.");
    }


    // Helper methods to write numbers in little-endian format into a byte array.
    // These mimic the behavior of methods in ServerMessageBlock for testing purposes.

    private void writeInt2(byte[] arr, int offset, int value) {
        arr[offset] = (byte) (value & 0xFF);
        arr[offset + 1] = (byte) ((value >> 8) & 0xFF);
    }

    private void writeInt4(byte[] arr, int offset, int value) {
        arr[offset] = (byte) (value & 0xFF);
        arr[offset + 1] = (byte) ((value >> 8) & 0xFF);
        arr[offset + 2] = (byte) ((value >> 16) & 0xFF);
        arr[offset + 3] = (byte) ((value >> 24) & 0xFF);
    }

    private void writeUTime(byte[] arr, int offset, long value) {
        // UTime is a 32-bit value representing seconds since the epoch.
        // The Java time is in milliseconds.
        if (value != 0) {
            writeInt4(arr, offset, (int) (value / 1000L));
        } else {
            writeInt4(arr, offset, 0);
        }
    }
}
