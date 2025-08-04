package jcifs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.dcerpc.DcerpcConstants;
import jcifs.dcerpc.msrpc.MsrpcDfsRootEnum;
import jcifs.dcerpc.msrpc.netdfs;
import jcifs.internal.smb1.net.SmbShareInfo;
import jcifs.smb.FileEntry;

@ExtendWith(MockitoExtension.class)
class MsrpcDfsRootEnumTest {

    private static final String TEST_SERVER = "testserver";

    // No need to mock the superclass constructor directly.
    // We will instantiate MsrpcDfsRootEnum and then use reflection to set its inherited fields.

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testConstructorInitialization() {
        // Create an instance of MsrpcDfsRootEnum
        MsrpcDfsRootEnum dfsRootEnum = new MsrpcDfsRootEnum(TEST_SERVER);

        // Verify that the constructor sets the correct level and ptype/flags
        assertEquals(200, dfsRootEnum.level, "Level should be 200");
        assertEquals(0, dfsRootEnum.getPtype(), "Ptype should be 0");
        assertEquals(DcerpcConstants.DCERPC_FIRST_FRAG | DcerpcConstants.DCERPC_LAST_FRAG, dfsRootEnum.getFlags(),
                "Flags should be correctly set");

        // Verify that the 'info' field (inherited from superclass)
        // has its 'level' and 'e' fields set correctly by MsrpcDfsRootEnum's constructor.
        assertNotNull(dfsRootEnum.info, "Info field should not be null");
        assertEquals(dfsRootEnum.level, dfsRootEnum.info.level, "Info level should match instance level");
        assertNotNull(dfsRootEnum.info.e, "Info.e should not be null");
        assertTrue(dfsRootEnum.info.e instanceof netdfs.DfsEnumArray200, "Info.e should be DfsEnumArray200");
    }

    @Test
    void testGetEntries_emptyArray() {
        MsrpcDfsRootEnum dfsRootEnum = new MsrpcDfsRootEnum(TEST_SERVER);

        // Mock the internal DfsEnumArray200 to return an empty array
        netdfs.DfsEnumArray200 mockArray = mock(netdfs.DfsEnumArray200.class);
        mockArray.count = 0;
        mockArray.s = new netdfs.DfsInfo200[0];

        // Use reflection to set the 'info.e' field of the real instance
        // This is necessary because the superclass constructor is called first,
        // and we need to inject our mock into the inherited 'info' field.
        try {
            java.lang.reflect.Field infoField = netdfs.NetrDfsEnumEx.class.getDeclaredField("info");
            infoField.setAccessible(true);
            netdfs.DfsEnumStruct info = (netdfs.DfsEnumStruct) infoField.get(dfsRootEnum);

            java.lang.reflect.Field eField = netdfs.DfsEnumStruct.class.getDeclaredField("e");
            eField.setAccessible(true);
            eField.set(info, mockArray);

        } catch (NoSuchFieldException | IllegalAccessException e) {
            fail("Failed to inject mock DfsEnumArray200: " + e.getMessage());
        }

        FileEntry[] entries = dfsRootEnum.getEntries();
        assertNotNull(entries, "Entries array should not be null");
        assertEquals(0, entries.length, "Entries array should be empty");
    }

    @Test
    void testGetEntries_populatedArray() {
        MsrpcDfsRootEnum dfsRootEnum = new MsrpcDfsRootEnum(TEST_SERVER);

        // Prepare mock DfsEnumArray200 with some entries
        netdfs.DfsEnumArray200 mockArray = mock(netdfs.DfsEnumArray200.class);
        mockArray.count = 2;
        mockArray.s = new netdfs.DfsInfo200[2];

        netdfs.DfsInfo200 entry1 = new netdfs.DfsInfo200();
        entry1.dfs_name = "share1";
        mockArray.s[0] = entry1;

        netdfs.DfsInfo200 entry2 = new netdfs.DfsInfo200();
        entry2.dfs_name = "share2";
        mockArray.s[1] = entry2;

        // Use reflection to set the 'info.e' field of the real instance
        try {
            java.lang.reflect.Field infoField = netdfs.NetrDfsEnumEx.class.getDeclaredField("info");
            infoField.setAccessible(true);
            netdfs.DfsEnumStruct info = (netdfs.DfsEnumStruct) infoField.get(dfsRootEnum);

            java.lang.reflect.Field eField = netdfs.DfsEnumStruct.class.getDeclaredField("e");
            eField.setAccessible(true);
            eField.set(info, mockArray);

        } catch (NoSuchFieldException | IllegalAccessException e) {
            fail("Failed to inject mock DfsEnumArray200: " + e.getMessage());
        }

        FileEntry[] entries = dfsRootEnum.getEntries();
        assertNotNull(entries, "Entries array should not be null");
        assertEquals(2, entries.length, "Entries array should have 2 elements");

        assertTrue(entries[0] instanceof SmbShareInfo, "First entry should be SmbShareInfo");
        assertEquals("share1", entries[0].getName(), "First entry name should match");

        assertTrue(entries[1] instanceof SmbShareInfo, "Second entry should be SmbShareInfo");
        assertEquals("share2", entries[1].getName(), "Second entry name should match");
    }
}