package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class SmbComQueryInformationTest {

    private static final String TEST_FILE_NAME = "testFile.txt";
    private SmbComQueryInformation smbComQueryInformation;

    @BeforeEach
    public void setUp() {
        smbComQueryInformation = new SmbComQueryInformation(TEST_FILE_NAME);
    }

    @Test
    @DisplayName("Constructor should set file name and command correctly")
    public void constructorShouldSetFileNameAndCommand() {
        // Test if the constructor sets the file name and command correctly
        assertEquals(TEST_FILE_NAME, smbComQueryInformation.path);
        assertEquals(ServerMessageBlock.SMB_COM_QUERY_INFORMATION, smbComQueryInformation.command);
    }

    @Test
    @DisplayName("writeParameterWordsWireFormat should do nothing and return zero")
    public void writeParameterWordsWireFormatShouldReturnZero() {
        // This method is expected to do nothing and return 0
        int result = smbComQueryInformation.writeParameterWordsWireFormat(new byte[0], 0);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("writeBytesWireFormat should write buffer format and file name")
    public void writeBytesWireFormatShouldWriteBufferFormatAndFileName() {
        // Test the writing of bytes to a byte array
        byte[] dst = new byte[100];
        int bytesWritten = smbComQueryInformation.writeBytesWireFormat(dst, 0);

        // Expected format: buffer format (1 byte) + file name (null-terminated)
        int expectedLength = 1 + TEST_FILE_NAME.length() + 1;
        assertEquals(expectedLength, bytesWritten);
        assertEquals(0x04, dst[0]); // Buffer format
        assertEquals(TEST_FILE_NAME, new String(dst, 1, TEST_FILE_NAME.length()));
    }

    @Test
    @DisplayName("readParameterWordsWireFormat should do nothing and return zero")
    public void readParameterWordsWireFormatShouldReturnZero() {
        // This method is expected to do nothing and return 0
        int result = smbComQueryInformation.readParameterWordsWireFormat(new byte[0], 0);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("readBytesWireFormat should do nothing and return zero")
    public void readBytesWireFormatShouldReturnZero() {
        // This method is expected to do nothing and return 0
        int result = smbComQueryInformation.readBytesWireFormat(new byte[0], 0);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("toString should return formatted string with class name and filename")
    public void toStringShouldReturnFormattedString() {
        // Test the string representation of the object
        String result = smbComQueryInformation.toString();
        assertTrue(result.startsWith("SmbComQueryInformation["));
        assertTrue(result.contains("filename=" + TEST_FILE_NAME));
    }
}
