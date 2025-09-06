package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Tests for the SmbComDeleteDirectory class.
 */
class SmbComDeleteDirectoryTest {

    /**
     * Test constructor.
     */
    @Test
    void testConstructor() {
        SmbComDeleteDirectory sdd = new SmbComDeleteDirectory("testDir");
        assertEquals("testDir", sdd.path);
        assertEquals(ServerMessageBlock.SMB_COM_DELETE_DIRECTORY, sdd.command);
    }

    /**
     * Test writeParameterWordsWireFormat.
     */
    @Test
    void testWriteParameterWordsWireFormat() {
        SmbComDeleteDirectory sdd = new SmbComDeleteDirectory("testDir");
        byte[] dst = new byte[10];
        int result = sdd.writeParameterWordsWireFormat(dst, 0);
        assertEquals(0, result);
    }

    /**
     * Test writeBytesWireFormat.
     */
    @Test
    void testWriteBytesWireFormat() {
        // Assuming path is ASCII and does not use unicode
        String dirName = "\testDir";
        SmbComDeleteDirectory sdd = new SmbComDeleteDirectory(dirName);
        sdd.useUnicode = false;
        // format byte + path + null terminator
        byte[] expected = new byte[1 + dirName.length() + 1];
        expected[0] = 0x04; // buffer format
        System.arraycopy(dirName.getBytes(), 0, expected, 1, dirName.length());
        expected[dirName.length() + 1] = 0x00; // null terminator

        byte[] dst = new byte[100];
        int len = sdd.writeBytesWireFormat(dst, 0);

        assertEquals(expected.length, len);

        byte[] result = new byte[len];
        System.arraycopy(dst, 0, result, 0, len);
        assertArrayEquals(expected, result);
    }

    /**
     * Test readParameterWordsWireFormat.
     */
    @Test
    void testReadParameterWordsWireFormat() {
        SmbComDeleteDirectory sdd = new SmbComDeleteDirectory("testDir");
        byte[] buffer = new byte[10];
        int result = sdd.readParameterWordsWireFormat(buffer, 0);
        assertEquals(0, result);
    }

    /**
     * Test readBytesWireFormat.
     */
    @Test
    void testReadBytesWireFormat() {
        SmbComDeleteDirectory sdd = new SmbComDeleteDirectory("testDir");
        byte[] buffer = new byte[10];
        int result = sdd.readBytesWireFormat(buffer, 0);
        assertEquals(0, result);
    }

    /**
     * Test toString method.
     */
    @Test
    void testToString() {
        SmbComDeleteDirectory sdd = new SmbComDeleteDirectory("testDir");
        String result = sdd.toString();
        assertTrue(result.contains("SmbComDeleteDirectory"));
        assertTrue(result.contains("directoryName=testDir"));
    }
}