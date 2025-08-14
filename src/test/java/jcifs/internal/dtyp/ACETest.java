package jcifs.internal.dtyp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import jcifs.smb.SID;
import jcifs.smb.SmbException;

/**
 * Test class for ACE (Access Control Entry)
 */
class ACETest {

    private ACE ace;
    private byte[] testBuffer;

    @BeforeEach
    void setUp() {
        ace = new ACE();
    }

    @Test
    @DisplayName("Test decode with allow ACE")
    void testDecodeAllowACE() throws Exception {
        // Prepare test data - Allow ACE
        testBuffer = new byte[100];
        testBuffer[0] = 0x00; // Allow ACE
        testBuffer[1] = 0x03; // FLAGS_OBJECT_INHERIT | FLAGS_CONTAINER_INHERIT
        testBuffer[2] = 0x20; // Size low byte (32)
        testBuffer[3] = 0x00; // Size high byte
        testBuffer[4] = (byte) 0xA9; // Access mask byte 0
        testBuffer[5] = 0x00; // Access mask byte 1
        testBuffer[6] = 0x12; // Access mask byte 2
        testBuffer[7] = 0x00; // Access mask byte 3

        // Add minimal SID data (S-1-1-0 - Everyone)
        testBuffer[8] = 0x01; // Revision
        testBuffer[9] = 0x01; // Sub-authority count
        testBuffer[10] = 0x00; // Identifier authority
        testBuffer[11] = 0x00;
        testBuffer[12] = 0x00;
        testBuffer[13] = 0x00;
        testBuffer[14] = 0x00;
        testBuffer[15] = 0x01;
        testBuffer[16] = 0x00; // Sub-authority
        testBuffer[17] = 0x00;
        testBuffer[18] = 0x00;
        testBuffer[19] = 0x00;

        // Test decode
        int size = ace.decode(testBuffer, 0, testBuffer.length);

        // Verify results
        assertEquals(32, size);
        assertTrue(ace.isAllow());
        assertEquals(0x03, ace.getFlags());
        assertEquals(0x001200A9, ace.getAccessMask());
        assertNotNull(ace.getSID());
    }

    @Test
    @DisplayName("Test decode with deny ACE")
    void testDecodeDenyACE() throws Exception {
        // Prepare test data - Deny ACE
        testBuffer = new byte[100];
        testBuffer[0] = 0x01; // Deny ACE (non-zero)
        testBuffer[1] = 0x10; // FLAGS_INHERITED
        testBuffer[2] = 0x24; // Size low byte (36)
        testBuffer[3] = 0x00; // Size high byte
        testBuffer[4] = (byte) 0xFF; // Access mask byte 0
        testBuffer[5] = 0x01; // Access mask byte 1
        testBuffer[6] = 0x1F; // Access mask byte 2
        testBuffer[7] = 0x00; // Access mask byte 3

        // Add minimal SID data
        testBuffer[8] = 0x01; // Revision
        testBuffer[9] = 0x01; // Sub-authority count
        testBuffer[10] = 0x00; // Identifier authority
        testBuffer[11] = 0x00;
        testBuffer[12] = 0x00;
        testBuffer[13] = 0x00;
        testBuffer[14] = 0x00;
        testBuffer[15] = 0x01;
        testBuffer[16] = 0x00; // Sub-authority
        testBuffer[17] = 0x00;
        testBuffer[18] = 0x00;
        testBuffer[19] = 0x00;

        // Test decode
        int size = ace.decode(testBuffer, 0, testBuffer.length);

        // Verify results
        assertEquals(36, size);
        assertFalse(ace.isAllow());
        assertEquals(0x10, ace.getFlags());
        assertEquals(0x001F01FF, ace.getAccessMask());
        assertTrue(ace.isInherited());
    }

    @Test
    @DisplayName("Test isInherited with FLAGS_INHERITED flag")
    void testIsInherited() {
        ace.flags = 0x00;
        assertFalse(ace.isInherited());

        ace.flags = ACE.FLAGS_INHERITED;
        assertTrue(ace.isInherited());

        ace.flags = ACE.FLAGS_INHERITED | ACE.FLAGS_OBJECT_INHERIT;
        assertTrue(ace.isInherited());
    }

    @ParameterizedTest
    @DisplayName("Test getApplyToText with different flag combinations")
    @CsvSource({ "0x00, This folder only", "'0x03', 'This folder, subfolders and files'", "0x0B, Subfolders and files only",
            "0x02, This folder and subfolders", "0x0A, Subfolders only", "0x01, This folder and files", "0x09, Files only",
            "0x08, Invalid" })
    void testGetApplyToText(String flagsHex, String expectedText) {
        ace.flags = Integer.parseInt(flagsHex.substring(2), 16);
        assertEquals(expectedText, ace.getApplyToText());
    }

    @Test
    @DisplayName("Test toString format for allow ACE")
    void testToStringAllowACE() throws SmbException {
        ace.allow = true;
        ace.access = 0x001200A9;
        ace.flags = 0x00;
        ace.sid = new SID("S-1-5-21-1234567890-123456789-123456789-1000");

        String result = ace.toString();

        assertTrue(result.startsWith("Allow "));
        // Hexdump.toHexString produces uppercase hex
        assertTrue(result.toLowerCase().contains("0x001200a9"));
        // ACE.toString() outputs "Direct    " with 4 spaces
        assertTrue(result.contains("Direct"));
        assertTrue(result.contains("This folder only"));
    }

    @Test
    @DisplayName("Test toString format for deny ACE")
    void testToStringDenyACE() throws SmbException {
        ace.allow = false;
        ace.access = 0x001F01FF;
        ace.flags = ACE.FLAGS_INHERITED | ACE.FLAGS_OBJECT_INHERIT | ACE.FLAGS_CONTAINER_INHERIT;
        ace.sid = new SID("S-1-5-32-544"); // Administrators

        String result = ace.toString();

        assertTrue(result.startsWith("Deny  "));
        // Hexdump.toHexString produces uppercase hex
        assertTrue(result.toLowerCase().contains("0x001f01ff"));
        // ACE.toString() outputs "Inherited " with 1 space
        assertTrue(result.contains("Inherited"));
        assertTrue(result.contains("This folder, subfolders and files"));
    }

    @Test
    @DisplayName("Test appendCol helper method")
    void testAppendCol() {
        StringBuffer sb = new StringBuffer();

        // Test with short string
        ace.appendCol(sb, "test", 10);
        assertEquals("test      ", sb.toString());

        // Test with exact width string
        sb = new StringBuffer();
        ace.appendCol(sb, "exact", 5);
        assertEquals("exact", sb.toString());

        // Test with longer string than width
        sb = new StringBuffer();
        ace.appendCol(sb, "longer string", 5);
        assertEquals("longer string", sb.toString());
    }

    @Test
    @DisplayName("Test getFlags returns correct value")
    void testGetFlags() {
        ace.flags = 0x00;
        assertEquals(0x00, ace.getFlags());

        ace.flags = 0xFF;
        assertEquals(0xFF, ace.getFlags());

        ace.flags = ACE.FLAGS_OBJECT_INHERIT | ACE.FLAGS_CONTAINER_INHERIT | ACE.FLAGS_INHERIT_ONLY;
        assertEquals(0x0B, ace.getFlags());
    }

    @Test
    @DisplayName("Test getAccessMask returns correct value")
    void testGetAccessMask() {
        ace.access = 0x00000000;
        assertEquals(0x00000000, ace.getAccessMask());

        ace.access = 0xFFFFFFFF;
        assertEquals(0xFFFFFFFF, ace.getAccessMask());

        ace.access = 0x001200A9;
        assertEquals(0x001200A9, ace.getAccessMask());
    }

    @Test
    @DisplayName("Test getSID returns correct SID")
    void testGetSID() throws SmbException {
        assertNull(ace.getSID());

        SID testSid = new SID("S-1-5-21-1234567890-123456789-123456789-1000");
        ace.sid = testSid;

        assertSame(testSid, ace.getSID());
    }

    @Test
    @DisplayName("Test decode with offset")
    void testDecodeWithOffset() {
        // Prepare test data with offset
        testBuffer = new byte[150];
        int offset = 50;

        testBuffer[offset] = 0x00; // Allow ACE
        testBuffer[offset + 1] = 0x08; // FLAGS_INHERIT_ONLY
        testBuffer[offset + 2] = 0x20; // Size low byte
        testBuffer[offset + 3] = 0x00; // Size high byte
        testBuffer[offset + 4] = 0x01; // Access mask byte 0
        testBuffer[offset + 5] = 0x00; // Access mask byte 1
        testBuffer[offset + 6] = 0x00; // Access mask byte 2
        testBuffer[offset + 7] = 0x00; // Access mask byte 3

        // Add minimal SID data
        testBuffer[offset + 8] = 0x01; // Revision
        testBuffer[offset + 9] = 0x01; // Sub-authority count
        for (int i = 0; i < 6; i++) {
            testBuffer[offset + 10 + i] = 0x00;
        }
        testBuffer[offset + 15] = 0x01;
        for (int i = 0; i < 4; i++) {
            testBuffer[offset + 16 + i] = 0x00;
        }

        // Test decode with offset
        int size = ace.decode(testBuffer, offset, testBuffer.length - offset);

        // Verify results
        assertEquals(32, size);
        assertTrue(ace.isAllow());
        assertEquals(0x08, ace.getFlags());
        assertEquals(0x00000001, ace.getAccessMask());
    }

    @ParameterizedTest
    @DisplayName("Test various access mask values")
    @ValueSource(ints = { 0x00000001, // FILE_READ_DATA
            0x00000002, // FILE_WRITE_DATA
            0x00000004, // FILE_APPEND_DATA
            0x00010000, // DELETE
            0x00020000, // READ_CONTROL
            0x00040000, // WRITE_DAC
            0x00080000, // WRITE_OWNER
            0x00100000, // SYNCHRONIZE
            0x10000000, // GENERIC_ALL
            0x20000000, // GENERIC_EXECUTE
            0x40000000, // GENERIC_WRITE
            0x80000000 // GENERIC_READ (as int will be negative)
    })
    void testVariousAccessMaskValues(int accessMask) {
        ace.access = accessMask;
        assertEquals(accessMask, ace.getAccessMask());
    }

    @Test
    @DisplayName("Test decode with max values")
    void testDecodeMaxValues() {
        testBuffer = new byte[100];
        testBuffer[0] = (byte) 0xFF; // Non-zero = Deny
        testBuffer[1] = (byte) 0xFF; // All flags
        testBuffer[2] = (byte) 0xFF; // Size low byte
        testBuffer[3] = (byte) 0xFF; // Size high byte
        testBuffer[4] = (byte) 0xFF; // Access mask all bits
        testBuffer[5] = (byte) 0xFF;
        testBuffer[6] = (byte) 0xFF;
        testBuffer[7] = (byte) 0xFF;

        // Add minimal SID data
        testBuffer[8] = 0x01;
        testBuffer[9] = 0x01;
        for (int i = 10; i < 20; i++) {
            testBuffer[i] = 0x00;
        }

        int size = ace.decode(testBuffer, 0, testBuffer.length);

        assertEquals(0xFFFF, size);
        assertFalse(ace.isAllow());
        assertEquals(0xFF, ace.getFlags());
        assertEquals(0xFFFFFFFF, ace.getAccessMask());
    }

    @Test
    @DisplayName("Test all flag combinations for inheritance")
    void testAllFlagCombinationsForInheritance() {
        // Test each individual flag
        ace.flags = ACE.FLAGS_OBJECT_INHERIT;
        assertFalse(ace.isInherited());

        ace.flags = ACE.FLAGS_CONTAINER_INHERIT;
        assertFalse(ace.isInherited());

        ace.flags = ACE.FLAGS_NO_PROPAGATE;
        assertFalse(ace.isInherited());

        ace.flags = ACE.FLAGS_INHERIT_ONLY;
        assertFalse(ace.isInherited());

        ace.flags = ACE.FLAGS_INHERITED;
        assertTrue(ace.isInherited());

        // Test combinations with FLAGS_INHERITED
        ace.flags = ACE.FLAGS_INHERITED | ACE.FLAGS_OBJECT_INHERIT;
        assertTrue(ace.isInherited());

        ace.flags = ACE.FLAGS_INHERITED | ACE.FLAGS_CONTAINER_INHERIT;
        assertTrue(ace.isInherited());

        ace.flags = ACE.FLAGS_INHERITED | ACE.FLAGS_NO_PROPAGATE;
        assertTrue(ace.isInherited());

        ace.flags = ACE.FLAGS_INHERITED | ACE.FLAGS_INHERIT_ONLY;
        assertTrue(ace.isInherited());
    }

    @Test
    @DisplayName("Test edge cases in getApplyToText")
    void testGetApplyToTextEdgeCases() {
        // Test with only FLAGS_INHERIT_ONLY (should return Invalid)
        ace.flags = ACE.FLAGS_INHERIT_ONLY;
        assertEquals("Invalid", ace.getApplyToText());

        // Test with FLAGS_NO_PROPAGATE (should not affect the result)
        ace.flags = ACE.FLAGS_OBJECT_INHERIT | ACE.FLAGS_CONTAINER_INHERIT | ACE.FLAGS_NO_PROPAGATE;
        assertEquals("This folder, subfolders and files", ace.getApplyToText());

        // Test with FLAGS_INHERITED (should not affect the result)
        ace.flags = ACE.FLAGS_OBJECT_INHERIT | ACE.FLAGS_INHERITED;
        assertEquals("This folder and files", ace.getApplyToText());

        // Test with high bits set (should mask to relevant bits)
        ace.flags = 0xF0 | ACE.FLAGS_CONTAINER_INHERIT;
        assertEquals("This folder and subfolders", ace.getApplyToText());
    }

    @Test
    @DisplayName("Test null SID handling in toString")
    void testToStringWithNullSID() {
        ace.allow = true;
        ace.access = 0x001200A9;
        ace.flags = 0x00;
        ace.sid = null;

        // This should throw NullPointerException as the current implementation doesn't handle null SID
        assertThrows(NullPointerException.class, () -> ace.toString());
    }

    @Test
    @DisplayName("Test decode creates new SID instance")
    void testDecodeCreatesNewSID() {
        testBuffer = new byte[100];
        testBuffer[0] = 0x00;
        testBuffer[1] = 0x00;
        testBuffer[2] = 0x20;
        testBuffer[3] = 0x00;
        testBuffer[4] = 0x00;
        testBuffer[5] = 0x00;
        testBuffer[6] = 0x00;
        testBuffer[7] = 0x00;

        // Add SID data
        testBuffer[8] = 0x01;
        testBuffer[9] = 0x01;
        for (int i = 10; i < 20; i++) {
            testBuffer[i] = 0x00;
        }

        assertNull(ace.getSID());

        ace.decode(testBuffer, 0, testBuffer.length);

        assertNotNull(ace.getSID());
    }
}
