package jcifs.internal.smb1.net;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import jcifs.SmbConstants;

/**
 * Test class for SmbShareInfo
 */
class SmbShareInfoTest {

    private SmbShareInfo shareInfo;
    private static final String TEST_NET_NAME = "TestShare";
    private static final String TEST_REMARK = "Test share remark";
    private static final int TEST_TYPE = 0x00000000; // Standard share type

    @BeforeEach
    void setUp() {
        shareInfo = new SmbShareInfo();
    }

    @Test
    @DisplayName("Test default constructor")
    void testDefaultConstructor() {
        // Verify default values
        assertNull(shareInfo.getName());
        assertEquals(SmbConstants.TYPE_SHARE, shareInfo.getType());
        assertEquals(0, shareInfo.getFileIndex());
        assertEquals(SmbConstants.ATTR_READONLY | SmbConstants.ATTR_DIRECTORY, shareInfo.getAttributes());
        assertEquals(0L, shareInfo.createTime());
        assertEquals(0L, shareInfo.lastModified());
        assertEquals(0L, shareInfo.lastAccess());
        assertEquals(0L, shareInfo.length());
    }

    @Test
    @DisplayName("Test parameterized constructor")
    void testParameterizedConstructor() {
        // Create instance with test values
        SmbShareInfo info = new SmbShareInfo(TEST_NET_NAME, TEST_TYPE, TEST_REMARK);
        
        // Verify all values are set correctly
        assertEquals(TEST_NET_NAME, info.getName());
        assertEquals(SmbConstants.TYPE_SHARE, info.getType());
        assertNotNull(info.toString());
        assertTrue(info.toString().contains(TEST_NET_NAME));
        assertTrue(info.toString().contains(TEST_REMARK));
    }

    @Test
    @DisplayName("Test getName method")
    void testGetName() {
        // Default constructor
        assertNull(shareInfo.getName());
        
        // With name set
        SmbShareInfo info = new SmbShareInfo(TEST_NET_NAME, TEST_TYPE, TEST_REMARK);
        assertEquals(TEST_NET_NAME, info.getName());
    }

    @Test
    @DisplayName("Test getFileIndex always returns 0")
    void testGetFileIndex() {
        // Default instance
        assertEquals(0, shareInfo.getFileIndex());
        
        // Instance with values
        SmbShareInfo info = new SmbShareInfo(TEST_NET_NAME, TEST_TYPE, TEST_REMARK);
        assertEquals(0, info.getFileIndex());
    }

    @ParameterizedTest
    @DisplayName("Test getType with different share types")
    @CsvSource({
        "1, " + SmbConstants.TYPE_PRINTER,      // Printer share
        "3, " + SmbConstants.TYPE_NAMED_PIPE,    // Named pipe
        "0, " + SmbConstants.TYPE_SHARE,         // Standard share
        "2, " + SmbConstants.TYPE_SHARE,         // Unknown type defaults to share
        "4, " + SmbConstants.TYPE_SHARE,         // Unknown type defaults to share
        "100, " + SmbConstants.TYPE_SHARE        // Unknown type defaults to share
    })
    void testGetTypeWithDifferentShareTypes(int inputType, int expectedType) {
        SmbShareInfo info = new SmbShareInfo(TEST_NET_NAME, inputType, TEST_REMARK);
        assertEquals(expectedType, info.getType());
    }

    @Test
    @DisplayName("Test getType with hidden flag")
    void testGetTypeWithHiddenFlag() {
        // Hidden flag (0x80000000) should be masked out
        int hiddenPrinterType = 0x80000001; // Hidden printer
        SmbShareInfo info = new SmbShareInfo(TEST_NET_NAME, hiddenPrinterType, TEST_REMARK);
        assertEquals(SmbConstants.TYPE_PRINTER, info.getType());
        
        int hiddenShareType = 0x80000000; // Hidden standard share
        info = new SmbShareInfo(TEST_NET_NAME, hiddenShareType, TEST_REMARK);
        assertEquals(SmbConstants.TYPE_SHARE, info.getType());
    }

    @Test
    @DisplayName("Test getAttributes always returns readonly directory")
    void testGetAttributes() {
        // Default instance
        assertEquals(SmbConstants.ATTR_READONLY | SmbConstants.ATTR_DIRECTORY, shareInfo.getAttributes());
        
        // Instance with values - attributes are still constant
        SmbShareInfo info = new SmbShareInfo(TEST_NET_NAME, TEST_TYPE, TEST_REMARK);
        assertEquals(SmbConstants.ATTR_READONLY | SmbConstants.ATTR_DIRECTORY, info.getAttributes());
    }

    @Test
    @DisplayName("Test time-related methods always return 0")
    void testTimeRelatedMethods() {
        // Default instance
        assertEquals(0L, shareInfo.createTime());
        assertEquals(0L, shareInfo.lastModified());
        assertEquals(0L, shareInfo.lastAccess());
        
        // Instance with values - times are still 0
        SmbShareInfo info = new SmbShareInfo(TEST_NET_NAME, TEST_TYPE, TEST_REMARK);
        assertEquals(0L, info.createTime());
        assertEquals(0L, info.lastModified());
        assertEquals(0L, info.lastAccess());
    }

    @Test
    @DisplayName("Test length always returns 0")
    void testLength() {
        // Default instance
        assertEquals(0L, shareInfo.length());
        
        // Instance with values - length is still 0
        SmbShareInfo info = new SmbShareInfo(TEST_NET_NAME, TEST_TYPE, TEST_REMARK);
        assertEquals(0L, info.length());
    }

    @Test
    @DisplayName("Test equals method with same netName")
    void testEqualsWithSameNetName() {
        SmbShareInfo info1 = new SmbShareInfo("Share1", 0, "Remark1");
        SmbShareInfo info2 = new SmbShareInfo("Share1", 1, "Remark2");
        
        // Same netName, different type and remark
        assertTrue(info1.equals(info2));
        assertTrue(info2.equals(info1));
    }

    @Test
    @DisplayName("Test equals method with different netName")
    void testEqualsWithDifferentNetName() {
        SmbShareInfo info1 = new SmbShareInfo("Share1", 0, "Remark");
        SmbShareInfo info2 = new SmbShareInfo("Share2", 0, "Remark");
        
        // Different netName
        assertFalse(info1.equals(info2));
        assertFalse(info2.equals(info1));
    }

    @Test
    @DisplayName("Test equals method with null netName")
    void testEqualsWithNullNetName() {
        SmbShareInfo info1 = new SmbShareInfo();
        SmbShareInfo info2 = new SmbShareInfo();
        
        // Both have null netName
        assertTrue(info1.equals(info2));
        
        SmbShareInfo info3 = new SmbShareInfo(TEST_NET_NAME, 0, TEST_REMARK);
        // One null, one non-null
        assertFalse(info1.equals(info3));
        assertFalse(info3.equals(info1));
    }

    @Test
    @DisplayName("Test equals method with same object")
    void testEqualsWithSameObject() {
        SmbShareInfo info = new SmbShareInfo(TEST_NET_NAME, TEST_TYPE, TEST_REMARK);
        assertTrue(info.equals(info));
    }

    @Test
    @DisplayName("Test equals method with different object type")
    void testEqualsWithDifferentObjectType() {
        SmbShareInfo info = new SmbShareInfo(TEST_NET_NAME, TEST_TYPE, TEST_REMARK);
        assertFalse(info.equals("Not a SmbShareInfo"));
        assertFalse(info.equals(null));
        assertFalse(info.equals(new Object()));
    }

    @Test
    @DisplayName("Test hashCode method")
    void testHashCode() {
        SmbShareInfo info1 = new SmbShareInfo(TEST_NET_NAME, 0, TEST_REMARK);
        SmbShareInfo info2 = new SmbShareInfo(TEST_NET_NAME, 1, "Different");
        
        // Same netName should have same hashCode
        assertEquals(info1.hashCode(), info2.hashCode());
        
        // Null netName
        SmbShareInfo info3 = new SmbShareInfo();
        assertEquals(0, info3.hashCode()); // Objects.hashCode(null) returns 0
    }

    @Test
    @DisplayName("Test hashCode consistency")
    void testHashCodeConsistency() {
        SmbShareInfo info = new SmbShareInfo(TEST_NET_NAME, TEST_TYPE, TEST_REMARK);
        int hashCode1 = info.hashCode();
        int hashCode2 = info.hashCode();
        
        // Multiple calls should return same value
        assertEquals(hashCode1, hashCode2);
    }

    @Test
    @DisplayName("Test toString method")
    void testToString() {
        SmbShareInfo info = new SmbShareInfo(TEST_NET_NAME, TEST_TYPE, TEST_REMARK);
        String str = info.toString();
        
        // Verify string contains expected elements
        assertNotNull(str);
        assertTrue(str.startsWith("SmbShareInfo["));
        assertTrue(str.contains("netName=" + TEST_NET_NAME));
        assertTrue(str.contains("type=0x"));
        assertTrue(str.contains("remark=" + TEST_REMARK));
        assertTrue(str.endsWith("]"));
    }

    @Test
    @DisplayName("Test toString with null values")
    void testToStringWithNullValues() {
        SmbShareInfo info = new SmbShareInfo();
        String str = info.toString();
        
        // Should handle null values gracefully
        assertNotNull(str);
        assertTrue(str.startsWith("SmbShareInfo["));
        assertTrue(str.contains("netName=null"));
        assertTrue(str.contains("type=0x"));
        assertTrue(str.contains("remark=null"));
        assertTrue(str.endsWith("]"));
    }

    @ParameterizedTest
    @DisplayName("Test toString with various type values")
    @ValueSource(ints = {0x00000000, 0x00000001, 0x00000003, 0x80000000, 0x80000001, 0xFFFFFFFF})
    void testToStringWithVariousTypes(int type) {
        SmbShareInfo info = new SmbShareInfo(TEST_NET_NAME, type, TEST_REMARK);
        String str = info.toString();
        
        // Verify type is displayed as hex
        assertNotNull(str);
        assertTrue(str.contains("type=0x"));
        // The type should be formatted as 8-character hex
        String expectedHex = String.format("%08x", type);
        assertTrue(str.toLowerCase().contains(expectedHex));
    }

    @Test
    @DisplayName("Test with empty strings")
    void testWithEmptyStrings() {
        SmbShareInfo info = new SmbShareInfo("", 0, "");
        
        assertEquals("", info.getName());
        assertEquals(SmbConstants.TYPE_SHARE, info.getType());
        
        // Test equals with empty string
        SmbShareInfo info2 = new SmbShareInfo("", 1, "Different");
        assertTrue(info.equals(info2));
        
        // HashCode for empty string
        assertEquals(0, info.hashCode()); // Empty string has hashCode of 0
    }

    @Test
    @DisplayName("Test with special characters in names")
    void testWithSpecialCharacters() {
        String specialName = "Share$\\Special/Name:*?";
        String specialRemark = "Remark with\nnewline\tand\rtabs";
        
        SmbShareInfo info = new SmbShareInfo(specialName, 0, specialRemark);
        
        assertEquals(specialName, info.getName());
        String str = info.toString();
        assertTrue(str.contains(specialName));
        assertTrue(str.contains(specialRemark));
    }

    @Test
    @DisplayName("Test type masking with 0xFFFF")
    void testTypeMasking() {
        // Test that only lower 16 bits are considered for type determination
        int typeWithUpperBits = 0xFFFF0001; // Should be treated as type 1 (printer)
        SmbShareInfo info = new SmbShareInfo(TEST_NET_NAME, typeWithUpperBits, TEST_REMARK);
        assertEquals(SmbConstants.TYPE_PRINTER, info.getType());
        
        typeWithUpperBits = 0x12340003; // Should be treated as type 3 (named pipe)
        info = new SmbShareInfo(TEST_NET_NAME, typeWithUpperBits, TEST_REMARK);
        assertEquals(SmbConstants.TYPE_NAMED_PIPE, info.getType());
    }

    @Test
    @DisplayName("Test FileEntry interface implementation")
    void testFileEntryInterface() {
        // Verify that SmbShareInfo properly implements FileEntry interface
        SmbShareInfo info = new SmbShareInfo(TEST_NET_NAME, TEST_TYPE, TEST_REMARK);
        
        // Cast to FileEntry to ensure interface is properly implemented
        jcifs.smb.FileEntry fileEntry = info;
        
        // Verify all FileEntry methods work
        assertEquals(TEST_NET_NAME, fileEntry.getName());
        assertEquals(0, fileEntry.getFileIndex());
        assertEquals(SmbConstants.TYPE_SHARE, fileEntry.getType());
        assertEquals(SmbConstants.ATTR_READONLY | SmbConstants.ATTR_DIRECTORY, fileEntry.getAttributes());
        assertEquals(0L, fileEntry.createTime());
        assertEquals(0L, fileEntry.lastModified());
        assertEquals(0L, fileEntry.lastAccess());
        assertEquals(0L, fileEntry.length());
    }
}
