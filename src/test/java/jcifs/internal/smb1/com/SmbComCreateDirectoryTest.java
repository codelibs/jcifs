package jcifs.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jcifs.Configuration;
import jcifs.internal.smb1.ServerMessageBlock;

/**
 * Tests for the SmbComCreateDirectory class.
 */
class SmbComCreateDirectoryTest {

    private Configuration mockConfig;

    @BeforeEach
    void setUp() {
        // Mock the Configuration object
        mockConfig = mock(Configuration.class);
        // Define behavior for the OEM encoding, which is used by writeString
        when(mockConfig.getOemEncoding()).thenReturn(StandardCharsets.UTF_8.name());
    }

    @Test
    void testConstructor() {
        // Test that the constructor correctly sets the command and path
        String directoryName = "testDir";
        SmbComCreateDirectory smbCom = new SmbComCreateDirectory(mockConfig, directoryName);

        assertEquals(ServerMessageBlock.SMB_COM_CREATE_DIRECTORY, smbCom.getCommand());
        assertEquals(directoryName, smbCom.getPath());
    }

    @Test
    void testWriteParameterWordsWireFormat() {
        // This method is empty, so it should return 0
        SmbComCreateDirectory smbCom = new SmbComCreateDirectory(mockConfig, "testDir");
        byte[] dst = new byte[10];
        int result = smbCom.writeParameterWordsWireFormat(dst, 0);
        assertEquals(0, result);
    }

    @Test
    void testWriteBytesWireFormat() {
        // Test the byte format written by the class
        String directoryName = "\testDir";
        SmbComCreateDirectory smbCom = new SmbComCreateDirectory(mockConfig, directoryName);

        // Expected format: buffer format (0x04) + path string (null terminated)
        byte[] expected = new byte[directoryName.length() + 2];
        expected[0] = 0x04; // Buffer format
        System.arraycopy(directoryName.getBytes(StandardCharsets.UTF_8), 0, expected, 1, directoryName.length());
        expected[directoryName.length() + 1] = 0x00; // Null terminator

        byte[] dst = new byte[100];
        int bytesWritten = smbCom.writeBytesWireFormat(dst, 0);

        assertEquals(expected.length, bytesWritten, "Number of bytes written should match expected length.");

        byte[] actual = new byte[bytesWritten];
        System.arraycopy(dst, 0, actual, 0, bytesWritten);

        // Use assertArrayEquals for byte array comparison
        org.junit.jupiter.api.Assertions.assertArrayEquals(expected, actual, "Byte array content should match the expected format.");
    }

    @Test
    void testReadParameterWordsWireFormat() {
        // This method is empty, so it should return 0
        SmbComCreateDirectory smbCom = new SmbComCreateDirectory(mockConfig, "testDir");
        byte[] buffer = new byte[10];
        int result = smbCom.readParameterWordsWireFormat(buffer, 0);
        assertEquals(0, result);
    }

    @Test
    void testReadBytesWireFormat() {
        // This method is empty, so it should return 0
        SmbComCreateDirectory smbCom = new SmbComCreateDirectory(mockConfig, "testDir");
        byte[] buffer = new byte[10];
        int result = smbCom.readBytesWireFormat(buffer, 0);
        assertEquals(0, result);
    }

    @Test
    void testToString() {
        // Test the string representation of the object
        String directoryName = "myDir";
        SmbComCreateDirectory smbCom = new SmbComCreateDirectory(mockConfig, directoryName);
        String actualString = smbCom.toString();

        // Check for key parts of the string representation
        org.junit.jupiter.api.Assertions.assertTrue(actualString.startsWith("SmbComCreateDirectory["),
                "String should start with the class name.");
        org.junit.jupiter.api.Assertions.assertTrue(actualString.contains("command=SMB_COM_CREATE_DIRECTORY"),
                "String should contain the command name.");
        org.junit.jupiter.api.Assertions.assertTrue(actualString.contains("directoryName=myDir"),
                "String should contain the directory name.");
        org.junit.jupiter.api.Assertions.assertTrue(actualString.endsWith("]"), "String should end with ']'");
    }
}
