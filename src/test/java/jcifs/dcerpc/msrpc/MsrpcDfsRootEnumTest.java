package jcifs.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import jcifs.dcerpc.msrpc.netdfs.DfsEnumArray200;
import jcifs.dcerpc.msrpc.netdfs.DfsInfo200;
import jcifs.smb.FileEntry;

/**
 * Tests for the MsrpcDfsRootEnum class.
 * This class uses JUnit 5 for testing.
 */
class MsrpcDfsRootEnumTest {

    /**
     * Test the constructor of MsrpcDfsRootEnum.
     * Verifies that the object is initialized with the correct default values.
     */
    @Test
    void testConstructor() {
        // Given
        String serverName = "test-server";

        // When
        MsrpcDfsRootEnum dfsRootEnum = new MsrpcDfsRootEnum(serverName);

        // Then
        assertNotNull(dfsRootEnum, "The MsrpcDfsRootEnum object should not be null.");
        // The server name is stored in a protected field without a public getter, so we cannot directly test it.
        // We can test the public fields that are set.
        assertEquals(200, dfsRootEnum.level, "The level should be initialized to 200.");
        assertNotNull(dfsRootEnum.info, "The info struct should not be null.");
        assertEquals(200, dfsRootEnum.info.level, "The info.level should be set to the same value as level.");
        assertTrue(dfsRootEnum.info.e instanceof DfsEnumArray200, "The info.e should be an instance of DfsEnumArray200.");
    }

    /**
     * Test the getEntries() method with a populated DfsEnumArray200.
     * Verifies that the DFS entries are correctly converted to FileEntry objects.
     */
    @Test
    void testGetEntries() {
        // Given
        MsrpcDfsRootEnum dfsRootEnum = new MsrpcDfsRootEnum("test-server");
        DfsEnumArray200 dfsEnumArray = new DfsEnumArray200();
        dfsEnumArray.count = 2;
        dfsEnumArray.s = new DfsInfo200[2];
        dfsEnumArray.s[0] = new DfsInfo200();
        dfsEnumArray.s[0].dfs_name = "\\domain\share1";
        dfsEnumArray.s[1] = new DfsInfo200();
        dfsEnumArray.s[1].dfs_name = "\\domain\share2";

        // Manually set the DfsEnumArray200 to the info struct
        dfsRootEnum.info.e = dfsEnumArray;

        // When
        FileEntry[] entries = dfsRootEnum.getEntries();

        // Then
        assertNotNull(entries, "The returned entries array should not be null.");
        assertEquals(2, entries.length, "The number of entries should be correct.");

        // The getEntries method returns FileEntry objects. We can check their names.
        assertEquals("\\domain\share1", entries[0].getName(), "The name of the first share should be correct.");
        assertEquals("\\domain\share2", entries[1].getName(), "The name of the second share should be correct.");
    }

    /**
     * Test the getEntries() method when the DfsEnumArray200 is empty.
     * Verifies that an empty array is returned.
     */
    @Test
    void testGetEntries_Empty() {
        // Given
        MsrpcDfsRootEnum dfsRootEnum = new MsrpcDfsRootEnum("test-server");
        DfsEnumArray200 dfsEnumArray = new DfsEnumArray200();
        dfsEnumArray.count = 0;
        dfsEnumArray.s = new DfsInfo200[0];

        // Manually set the DfsEnumArray200 to the info struct
        dfsRootEnum.info.e = dfsEnumArray;

        // When
        FileEntry[] entries = dfsRootEnum.getEntries();

        // Then
        assertNotNull(entries, "The returned entries array should not be null.");
        assertEquals(0, entries.length, "The entries array should be empty.");
    }
}
