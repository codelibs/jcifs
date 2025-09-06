package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class SmbShareInfoTest {

    /**
     * Test of constructor, of class SmbShareInfo.
     */
    @Test
    void testConstructor() {
        // Test no-argument constructor
        SmbShareInfo instance = new SmbShareInfo();
        assertNotNull(instance);

        // Test constructor with arguments
        String netName = "SHARE";
        int type = 1;
        String remark = "remark";
        instance = new SmbShareInfo(netName, type, remark);
        assertEquals(netName, instance.getName());
        // Note: getType() transforms the raw type
        assertEquals(SmbFile.TYPE_PRINTER, instance.getType());
    }

    /**
     * Test of getName method, of class SmbShareInfo.
     */
    @Test
    void testGetName() {
        String netName = "TEST_SHARE";
        SmbShareInfo instance = new SmbShareInfo(netName, 0, "remark");
        assertEquals(netName, instance.getName());
    }

    /**
     * Test of getType method, of class SmbShareInfo.
     */
    @Test
    void testGetType() {
        // Test for TYPE_PRINTER
        SmbShareInfo printerShare = new SmbShareInfo("PRINTER", 1, "A printer");
        assertEquals(SmbFile.TYPE_PRINTER, printerShare.getType());

        // Test for TYPE_NAMED_PIPE
        SmbShareInfo pipeShare = new SmbShareInfo("PIPE", 3, "A named pipe");
        assertEquals(SmbFile.TYPE_NAMED_PIPE, pipeShare.getType());

        // Test for TYPE_SHARE (disk share)
        SmbShareInfo diskShare = new SmbShareInfo("DISK", 0, "A disk share");
        assertEquals(SmbFile.TYPE_SHARE, diskShare.getType());

        // Test for another type that should default to TYPE_SHARE
        SmbShareInfo otherShare = new SmbShareInfo("OTHER", 2, "Another type");
        assertEquals(SmbFile.TYPE_SHARE, otherShare.getType());

        // Test with hidden flag (0x80000000) which should be ignored by getType()
        SmbShareInfo hiddenPrinter = new SmbShareInfo("HIDDEN_PRINTER", 1 | 0x80000000, "hidden printer");
        assertEquals(SmbFile.TYPE_PRINTER, hiddenPrinter.getType());
    }

    /**
     * Test of getAttributes method, of class SmbShareInfo.
     */
    @Test
    void testGetAttributes() {
        SmbShareInfo instance = new SmbShareInfo();
        int expResult = SmbFile.ATTR_READONLY | SmbFile.ATTR_DIRECTORY;
        int result = instance.getAttributes();
        assertEquals(expResult, result);
    }

    /**
     * Test of createTime method, of class SmbShareInfo.
     */
    @Test
    void testCreateTime() {
        SmbShareInfo instance = new SmbShareInfo();
        long expResult = 0L;
        long result = instance.createTime();
        assertEquals(expResult, result);
    }

    /**
     * Test of lastModified method, of class SmbShareInfo.
     */
    @Test
    void testLastModified() {
        SmbShareInfo instance = new SmbShareInfo();
        long expResult = 0L;
        long result = instance.lastModified();
        assertEquals(expResult, result);
    }

    /**
     * Test of length method, of class SmbShareInfo.
     */
    @Test
    void testLength() {
        SmbShareInfo instance = new SmbShareInfo();
        long expResult = 0L;
        long result = instance.length();
        assertEquals(expResult, result);
    }

    /**
     * Test of equals method, of class SmbShareInfo.
     */
    @Test
    void testEquals() {
        SmbShareInfo instance1 = new SmbShareInfo("SHARE1", 0, "remark1");
        SmbShareInfo instance2 = new SmbShareInfo("SHARE1", 1, "remark2");
        SmbShareInfo instance3 = new SmbShareInfo("SHARE2", 0, "remark1");
        Object notAShareInfo = new Object();

        assertTrue(instance1.equals(instance2)); // Should be equal based on netName
        assertFalse(instance1.equals(instance3)); // Should not be equal
        assertFalse(instance1.equals(notAShareInfo)); // Should not be equal to other types
        assertFalse(instance1.equals(null)); // Should not be equal to null
    }

    /**
     * Test of hashCode method, of class SmbShareInfo.
     */
    @Test
    void testHashCode() {
        SmbShareInfo instance1 = new SmbShareInfo("SHARE1", 0, "remark1");
        SmbShareInfo instance2 = new SmbShareInfo("SHARE1", 1, "remark2");
        SmbShareInfo instance3 = new SmbShareInfo("SHARE2", 0, "remark1");

        assertEquals(instance1.hashCode(), instance2.hashCode());
        assertNotEquals(instance1.hashCode(), instance3.hashCode());
    }

    /**
     * Test of toString method, of class SmbShareInfo.
     */
    @Test
    void testToString() {
        SmbShareInfo instance = new SmbShareInfo("SHARE", 2, "remark");
        String result = instance.toString();
        assertTrue(result.contains("netName=SHARE"));
        assertTrue(result.contains("type=0x00000002"));
        assertTrue(result.contains("remark=remark"));
    }
}
