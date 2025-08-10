package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import jcifs.smb1.smb1.ServerMessageBlock;
import jcifs.smb1.smb1.SmbComOpenAndX;
import jcifs.smb1.smb1.SmbFile;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests for the SmbComOpenAndX class.
 */
class SmbComOpenAndXTest {

    private SmbComOpenAndX smbComOpenAndX;
    private final String fileName = "testFile.txt";
    private final int access = SmbFile.GENERIC_READ | SmbFile.GENERIC_WRITE;
    private ServerMessageBlock andx;

    /**
     * Sets up the test environment before each test.
     */
    @BeforeEach
    void setUp() {
        andx = mock(ServerMessageBlock.class);
    }

    /**
     * Test constructor with O_CREAT and O_TRUNC flags.
     */
    @Test
    void testConstructor_CreateAndTruncate() {
        int flags = SmbFile.O_CREAT | SmbFile.O_TRUNC;
        smbComOpenAndX = new SmbComOpenAndX(fileName, access, flags, andx);
        assertEquals(fileName, smbComOpenAndX.path);
        assertEquals(ServerMessageBlock.SMB_COM_OPEN_ANDX, smbComOpenAndX.command);
        assertEquals(0x12, smbComOpenAndX.openFunction); // OPEN_FN_CREATE | OPEN_FN_TRUNC
    }

    /**
     * Test constructor with O_CREAT and O_EXCL flags.
     */
    @Test
    void testConstructor_CreateAndFailIfExists() {
        int flags = SmbFile.O_CREAT | SmbFile.O_EXCL;
        smbComOpenAndX = new SmbComOpenAndX(fileName, access, flags, andx);
        assertEquals(0x10, smbComOpenAndX.openFunction); // OPEN_FN_CREATE | OPEN_FN_FAIL_IF_EXISTS
    }

    /**
     * Test constructor with O_CREAT flag.
     */
    @Test
    void testConstructor_CreateAndOpen() {
        int flags = SmbFile.O_CREAT;
        smbComOpenAndX = new SmbComOpenAndX(fileName, access, flags, andx);
        assertEquals(0x11, smbComOpenAndX.openFunction); // OPEN_FN_CREATE | OPEN_FN_OPEN
    }

    /**
     * Test constructor with no special flags.
     */
    @Test
    void testConstructor_OpenOnly() {
        int flags = 0;
        smbComOpenAndX = new SmbComOpenAndX(fileName, access, flags, andx);
        assertEquals(0x01, smbComOpenAndX.openFunction); // OPEN_FN_OPEN
    }

    /**
     * Test constructor with O_TRUNC flag.
     */
    @Test
    void testConstructor_TruncateOnly() {
        int flags = SmbFile.O_TRUNC;
        smbComOpenAndX = new SmbComOpenAndX(fileName, access, flags, andx);
        assertEquals(0x02, smbComOpenAndX.openFunction); // OPEN_FN_TRUNC
    }

    /**
     * Test getBatchLimit with SMB_COM_READ_ANDX command.
     */
    @Test
    void testGetBatchLimit_ReadAndX() {
        smbComOpenAndX = new SmbComOpenAndX(fileName, access, 0, andx);
        assertEquals(1, smbComOpenAndX.getBatchLimit(ServerMessageBlock.SMB_COM_READ_ANDX));
    }

    /**
     * Test getBatchLimit with a command other than SMB_COM_READ_ANDX.
     */
    @Test
    void testGetBatchLimit_OtherCommand() {
        smbComOpenAndX = new SmbComOpenAndX(fileName, access, 0, andx);
        assertEquals(0, smbComOpenAndX.getBatchLimit(ServerMessageBlock.SMB_COM_WRITE_ANDX));
    }

    /**
     * Test writeParameterWordsWireFormat method.
     */
    @Test
    void testWriteParameterWordsWireFormat() {
        smbComOpenAndX = new SmbComOpenAndX(fileName, access, 0, andx);
        // Buffer needs 26 bytes: 2+2+2+2+4+2+4+8 = 26
        byte[] dst = new byte[26];
        int result = smbComOpenAndX.writeParameterWordsWireFormat(dst, 0);
        assertEquals(26, result);
    }

    /**
     * Test writeBytesWireFormat method with Unicode.
     */
    @Test
    void testWriteBytesWireFormat_Unicode() {
        smbComOpenAndX = new SmbComOpenAndX(fileName, access, 0, andx);
        smbComOpenAndX.useUnicode = true;
        // For Unicode: 1 byte (initial null in writeBytesWireFormat) 
        // + potential 1 byte alignment (in writeString) + fileName.length() * 2 + 2 bytes (terminating nulls)
        // Since headerStart is 0 and dstIndex starts at 1 (after initial null), (1-0)%2=1, so alignment byte added
        // Total: 1 + 1 + 12*2 + 2 = 28 bytes
        byte[] dst = new byte[30]; // Use extra buffer space to avoid index errors
        int result = smbComOpenAndX.writeBytesWireFormat(dst, 0);
        assertEquals(28, result);
    }

    /**
     * Test writeBytesWireFormat method without Unicode.
     */
    @Test
    void testWriteBytesWireFormat_NoUnicode() {
        smbComOpenAndX = new SmbComOpenAndX(fileName, access, 0, andx);
        smbComOpenAndX.useUnicode = false;
        byte[] dst = new byte[fileName.length() + 1];
        int result = smbComOpenAndX.writeBytesWireFormat(dst, 0);
        assertEquals(fileName.length() + 1, result);
    }

    /**
     * Test readParameterWordsWireFormat method.
     */
    @Test
    void testReadParameterWordsWireFormat() {
        smbComOpenAndX = new SmbComOpenAndX(fileName, access, 0, andx);
        byte[] buffer = new byte[0];
        int result = smbComOpenAndX.readParameterWordsWireFormat(buffer, 0);
        assertEquals(0, result);
    }

    /**
     * Test readBytesWireFormat method.
     */
    @Test
    void testReadBytesWireFormat() {
        smbComOpenAndX = new SmbComOpenAndX(fileName, access, 0, andx);
        byte[] buffer = new byte[0];
        int result = smbComOpenAndX.readBytesWireFormat(buffer, 0);
        assertEquals(0, result);
    }

    /**
     * Test toString method.
     */
    @Test
    void testToString() {
        smbComOpenAndX = new SmbComOpenAndX(fileName, access, 0, andx);
        String result = smbComOpenAndX.toString();
        assertNotNull(result);
        assertTrue(result.contains(fileName));
    }
}