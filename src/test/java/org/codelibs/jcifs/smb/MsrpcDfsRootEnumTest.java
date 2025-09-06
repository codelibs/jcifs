package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;

import org.codelibs.jcifs.smb.dcerpc.DcerpcConstants;
import org.codelibs.jcifs.smb.dcerpc.msrpc.MsrpcDfsRootEnum;
import org.codelibs.jcifs.smb.dcerpc.msrpc.netdfs;
import org.codelibs.jcifs.smb.internal.smb1.net.SmbShareInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class MsrpcDfsRootEnumTest {

    private static final String TEST_SERVER = "testserver";
    private MsrpcDfsRootEnum dfsRootEnum;

    @BeforeEach
    void setUp() {
        dfsRootEnum = new MsrpcDfsRootEnum(TEST_SERVER);
    }

    @Test
    @DisplayName("Constructor should initialize all fields correctly")
    void testConstructorInitialization() {
        // Verify level is set to 200 for DFS root enumeration
        assertEquals(200, dfsRootEnum.level);

        // Verify DCE/RPC message properties
        assertEquals(0, dfsRootEnum.getPtype());
        assertEquals(DcerpcConstants.DCERPC_FIRST_FRAG | DcerpcConstants.DCERPC_LAST_FRAG, dfsRootEnum.getFlags());

        // Verify DFS enumeration structure
        assertNotNull(dfsRootEnum.info);
        assertEquals(200, dfsRootEnum.info.level);
        assertNotNull(dfsRootEnum.info.e);
        assertInstanceOf(netdfs.DfsEnumArray200.class, dfsRootEnum.info.e);

        // Verify DFS name is set to server name
        assertEquals(TEST_SERVER, dfsRootEnum.dfs_name);

        // Verify preferred max length is set to maximum
        assertEquals(0xFFFF, dfsRootEnum.prefmaxlen);

        // Verify totalentries is initialized
        assertNotNull(dfsRootEnum.totalentries);
    }

    @Test
    @DisplayName("getEntries should return empty array when no DFS roots exist")
    void testGetEntries_emptyArray() throws Exception {
        // Create empty DfsEnumArray200
        netdfs.DfsEnumArray200 emptyArray = new netdfs.DfsEnumArray200();
        emptyArray.count = 0;
        emptyArray.s = new netdfs.DfsInfo200[0];

        // Replace the info.e field with our empty array
        setDfsEnumArray(dfsRootEnum, emptyArray);

        // Test getEntries returns empty array
        FileEntry[] entries = dfsRootEnum.getEntries();
        assertNotNull(entries);
        assertEquals(0, entries.length);
    }

    @Test
    @DisplayName("getEntries should return SmbShareInfo array for DFS roots")
    void testGetEntries_populatedArray() throws Exception {
        // Create populated DfsEnumArray200
        netdfs.DfsEnumArray200 populatedArray = new netdfs.DfsEnumArray200();
        populatedArray.count = 3;
        populatedArray.s = new netdfs.DfsInfo200[3];

        // Create DFS root entries
        String[] rootNames = { "share1", "share2", "share3" };
        for (int i = 0; i < 3; i++) {
            netdfs.DfsInfo200 entry = new netdfs.DfsInfo200();
            entry.dfs_name = rootNames[i];
            populatedArray.s[i] = entry;
        }

        // Replace the info.e field with our populated array
        setDfsEnumArray(dfsRootEnum, populatedArray);

        // Test getEntries returns correct SmbShareInfo objects
        FileEntry[] entries = dfsRootEnum.getEntries();
        assertNotNull(entries);
        assertEquals(3, entries.length);

        // Verify each entry
        for (int i = 0; i < 3; i++) {
            assertInstanceOf(SmbShareInfo.class, entries[i]);
            assertEquals(rootNames[i], entries[i].getName());
            assertEquals(8, entries[i].getType()); // TYPE_SHARE constant value
        }
    }

    @Test
    @DisplayName("getEntries should handle single DFS root correctly")
    void testGetEntries_singleEntry() throws Exception {
        // Create array with single entry
        netdfs.DfsEnumArray200 singleArray = new netdfs.DfsEnumArray200();
        singleArray.count = 1;
        singleArray.s = new netdfs.DfsInfo200[1];

        netdfs.DfsInfo200 entry = new netdfs.DfsInfo200();
        entry.dfs_name = "single_share";
        singleArray.s[0] = entry;

        // Replace the info.e field
        setDfsEnumArray(dfsRootEnum, singleArray);

        // Test getEntries
        FileEntry[] entries = dfsRootEnum.getEntries();
        assertNotNull(entries);
        assertEquals(1, entries.length);
        assertInstanceOf(SmbShareInfo.class, entries[0]);
        assertEquals("single_share", entries[0].getName());
        assertEquals(8, entries[0].getType()); // TYPE_SHARE constant value
    }

    @Test
    @DisplayName("getEntries should handle null DFS names gracefully")
    void testGetEntries_nullNames() throws Exception {
        // Create array with null name entries
        netdfs.DfsEnumArray200 arrayWithNulls = new netdfs.DfsEnumArray200();
        arrayWithNulls.count = 2;
        arrayWithNulls.s = new netdfs.DfsInfo200[2];

        netdfs.DfsInfo200 entry1 = new netdfs.DfsInfo200();
        entry1.dfs_name = null;
        arrayWithNulls.s[0] = entry1;

        netdfs.DfsInfo200 entry2 = new netdfs.DfsInfo200();
        entry2.dfs_name = "valid_share";
        arrayWithNulls.s[1] = entry2;

        // Replace the info.e field
        setDfsEnumArray(dfsRootEnum, arrayWithNulls);

        // Test getEntries handles nulls
        FileEntry[] entries = dfsRootEnum.getEntries();
        assertNotNull(entries);
        assertEquals(2, entries.length);

        assertInstanceOf(SmbShareInfo.class, entries[0]);
        assertNull(entries[0].getName());
        assertEquals(8, entries[0].getType()); // TYPE_SHARE constant value

        assertInstanceOf(SmbShareInfo.class, entries[1]);
        assertEquals("valid_share", entries[1].getName());
        assertEquals(8, entries[1].getType()); // TYPE_SHARE constant value
    }

    @Test
    @DisplayName("DCE/RPC flags should be set correctly")
    void testDcerpcFlags() {
        // Test individual flag checking
        assertTrue(dfsRootEnum.isFlagSet(DcerpcConstants.DCERPC_FIRST_FRAG));
        assertTrue(dfsRootEnum.isFlagSet(DcerpcConstants.DCERPC_LAST_FRAG));

        // Combined flags should equal FIRST_FRAG | LAST_FRAG
        int expectedFlags = DcerpcConstants.DCERPC_FIRST_FRAG | DcerpcConstants.DCERPC_LAST_FRAG;
        assertEquals(expectedFlags, dfsRootEnum.getFlags());
    }

    @Test
    @DisplayName("Multiple server names should be handled correctly")
    void testDifferentServerNames() {
        // Test with different server names
        String[] serverNames = { "server1", "domain.local", "192.168.1.100", "FILESERVER" };

        for (String serverName : serverNames) {
            MsrpcDfsRootEnum enumInstance = new MsrpcDfsRootEnum(serverName);
            assertEquals(serverName, enumInstance.dfs_name);
            assertEquals(200, enumInstance.level);
            assertNotNull(enumInstance.info);
        }
    }

    @Test
    @DisplayName("getEntries should properly convert DFS roots with special characters")
    void testGetEntries_specialCharacters() throws Exception {
        // Create array with special character names
        netdfs.DfsEnumArray200 specialArray = new netdfs.DfsEnumArray200();
        specialArray.count = 3;
        specialArray.s = new netdfs.DfsInfo200[3];

        String[] specialNames = { "share$", "admin-share", "share_with_underscore" };
        for (int i = 0; i < 3; i++) {
            netdfs.DfsInfo200 entry = new netdfs.DfsInfo200();
            entry.dfs_name = specialNames[i];
            specialArray.s[i] = entry;
        }

        // Replace the info.e field
        setDfsEnumArray(dfsRootEnum, specialArray);

        // Test getEntries handles special characters
        FileEntry[] entries = dfsRootEnum.getEntries();
        assertNotNull(entries);
        assertEquals(3, entries.length);

        for (int i = 0; i < 3; i++) {
            assertInstanceOf(SmbShareInfo.class, entries[i]);
            assertEquals(specialNames[i], entries[i].getName());
            assertEquals(8, entries[i].getType()); // TYPE_SHARE constant value
        }
    }

    @Test
    @DisplayName("getEntries should handle large number of DFS roots")
    void testGetEntries_largeNumberOfRoots() throws Exception {
        // Create array with many entries
        int count = 100;
        netdfs.DfsEnumArray200 largeArray = new netdfs.DfsEnumArray200();
        largeArray.count = count;
        largeArray.s = new netdfs.DfsInfo200[count];

        for (int i = 0; i < count; i++) {
            netdfs.DfsInfo200 entry = new netdfs.DfsInfo200();
            entry.dfs_name = "share_" + i;
            largeArray.s[i] = entry;
        }

        // Replace the info.e field
        setDfsEnumArray(dfsRootEnum, largeArray);

        // Test getEntries handles large arrays
        FileEntry[] entries = dfsRootEnum.getEntries();
        assertNotNull(entries);
        assertEquals(count, entries.length);

        for (int i = 0; i < count; i++) {
            assertInstanceOf(SmbShareInfo.class, entries[i]);
            assertEquals("share_" + i, entries[i].getName());
            assertEquals(8, entries[i].getType());
        }
    }

    @Test
    @DisplayName("Constructor should use default DCE/RPC parameters")
    void testConstructorDefaults() {
        // Verify default parameters are set correctly
        assertEquals(0, dfsRootEnum.getPtype());
        assertEquals(0xFFFF, dfsRootEnum.prefmaxlen);
        assertEquals(0, dfsRootEnum.totalentries.value);

        // Verify info structure is properly initialized
        assertNotNull(dfsRootEnum.info);
        assertEquals(200, dfsRootEnum.info.level);
        assertNotNull(dfsRootEnum.info.e);
    }

    @Test
    @DisplayName("getEntries should return consistent results on multiple calls")
    void testGetEntries_multipleCallsConsistency() throws Exception {
        // Setup test data
        netdfs.DfsEnumArray200 testArray = new netdfs.DfsEnumArray200();
        testArray.count = 2;
        testArray.s = new netdfs.DfsInfo200[2];

        for (int i = 0; i < 2; i++) {
            netdfs.DfsInfo200 entry = new netdfs.DfsInfo200();
            entry.dfs_name = "consistent_share_" + i;
            testArray.s[i] = entry;
        }

        setDfsEnumArray(dfsRootEnum, testArray);

        // Call getEntries multiple times
        FileEntry[] entries1 = dfsRootEnum.getEntries();
        FileEntry[] entries2 = dfsRootEnum.getEntries();
        FileEntry[] entries3 = dfsRootEnum.getEntries();

        // Verify consistency
        assertNotNull(entries1);
        assertNotNull(entries2);
        assertNotNull(entries3);

        assertEquals(entries1.length, entries2.length);
        assertEquals(entries2.length, entries3.length);

        for (int i = 0; i < entries1.length; i++) {
            assertEquals(entries1[i].getName(), entries2[i].getName());
            assertEquals(entries2[i].getName(), entries3[i].getName());
            assertEquals(entries1[i].getType(), entries2[i].getType());
            assertEquals(entries2[i].getType(), entries3[i].getType());
        }
    }

    @Test
    @DisplayName("Verify proper inheritance and interface implementation")
    void testInheritance() {
        // Verify MsrpcDfsRootEnum extends netdfs.NetrDfsEnumEx
        assertInstanceOf(netdfs.NetrDfsEnumEx.class, dfsRootEnum);

        // Verify it's a DCE/RPC message
        assertInstanceOf(org.codelibs.jcifs.smb.dcerpc.DcerpcMessage.class, dfsRootEnum);
    }

    @Test
    @DisplayName("getEntries should handle empty string DFS names")
    void testGetEntries_emptyStringNames() throws Exception {
        // Create array with empty string names
        netdfs.DfsEnumArray200 emptyNameArray = new netdfs.DfsEnumArray200();
        emptyNameArray.count = 2;
        emptyNameArray.s = new netdfs.DfsInfo200[2];

        netdfs.DfsInfo200 entry1 = new netdfs.DfsInfo200();
        entry1.dfs_name = "";
        emptyNameArray.s[0] = entry1;

        netdfs.DfsInfo200 entry2 = new netdfs.DfsInfo200();
        entry2.dfs_name = "normal_share";
        emptyNameArray.s[1] = entry2;

        // Replace the info.e field
        setDfsEnumArray(dfsRootEnum, emptyNameArray);

        // Test getEntries handles empty strings
        FileEntry[] entries = dfsRootEnum.getEntries();
        assertNotNull(entries);
        assertEquals(2, entries.length);

        assertInstanceOf(SmbShareInfo.class, entries[0]);
        assertEquals("", entries[0].getName());
        assertEquals(8, entries[0].getType());

        assertInstanceOf(SmbShareInfo.class, entries[1]);
        assertEquals("normal_share", entries[1].getName());
        assertEquals(8, entries[1].getType());
    }

    // Helper method to set DfsEnumArray using reflection
    private void setDfsEnumArray(MsrpcDfsRootEnum target, netdfs.DfsEnumArray200 array) throws Exception {
        Field eField = netdfs.DfsEnumStruct.class.getDeclaredField("e");
        eField.setAccessible(true);
        eField.set(target.info, array);
    }
}