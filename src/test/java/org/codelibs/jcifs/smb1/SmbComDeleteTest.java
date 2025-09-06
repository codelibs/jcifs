package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;

import org.codelibs.jcifs.smb1.util.Hexdump;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class SmbComDeleteTest {

    private static final String TEST_FILE_NAME = "testFile.txt";
    private SmbComDelete smbComDelete;

    @BeforeEach
    public void setUp() {
        smbComDelete = new SmbComDelete(TEST_FILE_NAME);
    }

    @Test
    public void testConstructor() {
        // Test if the constructor sets the file name and command correctly
        assertEquals(TEST_FILE_NAME, smbComDelete.path);
        assertEquals(ServerMessageBlock.SMB_COM_DELETE, smbComDelete.command);
    }

    @Test
    public void testWriteParameterWordsWireFormat() {
        // Test the writing of parameter words to a byte array
        byte[] dst = new byte[2];
        int bytesWritten = smbComDelete.writeParameterWordsWireFormat(dst, 0);
        assertEquals(2, bytesWritten);
        // ATTR_HIDDEN (0x02) | ATTR_SYSTEM (0x04) = 0x06
        assertEquals(0x06, dst[0]);
        assertEquals(0x00, dst[1]);
    }

    @Test
    public void testWriteBytesWireFormat() {
        // Test the writing of bytes to a byte array
        byte[] dst = new byte[100];
        int bytesWritten = smbComDelete.writeBytesWireFormat(dst, 0);

        // Expected format: buffer format (1 byte) + file name (null-terminated)
        int expectedLength = 1 + TEST_FILE_NAME.length() + 1;
        assertEquals(expectedLength, bytesWritten);
        assertEquals(0x04, dst[0]); // Buffer format
        assertEquals(TEST_FILE_NAME, new String(dst, 1, TEST_FILE_NAME.length()));
    }

    @Test
    public void testReadParameterWordsWireFormat() {
        // This method is expected to do nothing and return 0
        int result = smbComDelete.readParameterWordsWireFormat(new byte[0], 0);
        assertEquals(0, result);
    }

    @Test
    public void testReadBytesWireFormat() {
        // This method is expected to do nothing and return 0
        int result = smbComDelete.readBytesWireFormat(new byte[0], 0);
        assertEquals(0, result);
    }

    @Test
    public void testToString() {
        // Test the string representation of the object
        String result = smbComDelete.toString();
        assertNotNull(result);

        // Verify the result contains expected components
        assertTrue(result.startsWith("SmbComDelete["));
        assertTrue(result.contains("searchAttributes=0x"));
        assertTrue(result.contains("fileName=" + TEST_FILE_NAME));

        // Get private searchAttributes field to verify the hex value
        int searchAttributes = getSearchAttributes(smbComDelete);
        String expectedSearchAttributes = "searchAttributes=0x" + Hexdump.toHexString(searchAttributes, 4);
        assertTrue(result.contains(expectedSearchAttributes));
    }

    // Helper method to get private searchAttributes field using reflection
    private int getSearchAttributes(SmbComDelete smbComDelete) {
        try {
            Field field = smbComDelete.getClass().getDeclaredField("searchAttributes");
            field.setAccessible(true);
            return field.getInt(smbComDelete);
        } catch (Exception e) {
            throw new RuntimeException("Failed to get searchAttributes field", e);
        }
    }
}
