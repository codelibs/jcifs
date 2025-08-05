package jcifs.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.lang.reflect.Field;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jcifs.internal.smb1.net.SmbShareInfo;
import jcifs.smb.FileEntry;

class MsrpcShareEnumTest {

    private static final String TEST_SERVER_NAME = "testServer";

    private MsrpcShareEnum msrpcShareEnum;

    @BeforeEach
    void setUp() {
        msrpcShareEnum = new MsrpcShareEnum(TEST_SERVER_NAME);
    }

    @Test
    void testConstructor() {
        // Test that the constructor initializes the object correctly
        MsrpcShareEnum shareEnum = new MsrpcShareEnum(TEST_SERVER_NAME);
        assertNotNull(shareEnum);
        
        // Verify the server name is properly formatted with double backslashes
        try {
            Field servernameField = srvsvc.ShareEnumAll.class.getDeclaredField("servername");
            servernameField.setAccessible(true);
            String servername = (String) servernameField.get(shareEnum);
            assertEquals("\\\\" + TEST_SERVER_NAME, servername);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            fail("Failed to access servername field: " + e.getMessage());
        }
    }

    @Test
    void testGetEntriesWithMultipleShares() throws Exception {
        // Create real ShareInfo1 objects instead of mocks
        srvsvc.ShareInfo1 shareInfo1 = new srvsvc.ShareInfo1();
        shareInfo1.netname = "Share1";
        shareInfo1.type = 0;
        shareInfo1.remark = "Remark for Share1";

        srvsvc.ShareInfo1 shareInfo2 = new srvsvc.ShareInfo1();
        shareInfo2.netname = "Share2";
        shareInfo2.type = 1;
        shareInfo2.remark = "Remark for Share2";

        // Create ShareInfoCtr1 with the shares
        srvsvc.ShareInfoCtr1 shareInfoCtr1 = new srvsvc.ShareInfoCtr1();
        shareInfoCtr1.count = 2;
        shareInfoCtr1.array = new srvsvc.ShareInfo1[] { shareInfo1, shareInfo2 };

        // Inject the ShareInfoCtr1 using reflection
        Field infoField = srvsvc.ShareEnumAll.class.getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(msrpcShareEnum, shareInfoCtr1);

        // Test getEntries method
        FileEntry[] entries = msrpcShareEnum.getEntries();

        assertNotNull(entries);
        assertEquals(2, entries.length);

        // Verify the first entry
        FileEntry entry1 = entries[0];
        assertNotNull(entry1);
        assertEquals("Share1", entry1.getName());
        assertEquals(8, entry1.getType()); // TYPE_SHARE constant
        
        // Access remark through SmbShareInfo methods if available
        assertTrue(entry1 instanceof SmbShareInfo);
        SmbShareInfo shareInfo = (SmbShareInfo) entry1;
        Field remarkField = SmbShareInfo.class.getDeclaredField("remark");
        remarkField.setAccessible(true);
        assertEquals("Remark for Share1", remarkField.get(shareInfo));

        // Verify the second entry
        FileEntry entry2 = entries[1];
        assertNotNull(entry2);
        assertEquals("Share2", entry2.getName());
        assertEquals(32, entry2.getType()); // TYPE_PRINTER constant (0x20)
    }

    @Test
    void testGetEntriesWithNoShares() throws Exception {
        // Create empty ShareInfoCtr1
        srvsvc.ShareInfoCtr1 shareInfoCtr1 = new srvsvc.ShareInfoCtr1();
        shareInfoCtr1.count = 0;
        shareInfoCtr1.array = new srvsvc.ShareInfo1[0];

        // Inject the ShareInfoCtr1 using reflection
        Field infoField = srvsvc.ShareEnumAll.class.getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(msrpcShareEnum, shareInfoCtr1);

        // Test getEntries method
        FileEntry[] entries = msrpcShareEnum.getEntries();

        assertNotNull(entries);
        assertEquals(0, entries.length);
    }

    @Test
    void testGetEntriesWithSingleShare() throws Exception {
        // Create a single ShareInfo1 object
        srvsvc.ShareInfo1 shareInfo = new srvsvc.ShareInfo1();
        shareInfo.netname = "SingleShare";
        shareInfo.type = 2;
        shareInfo.remark = "Single share remark";

        // Create ShareInfoCtr1 with one share
        srvsvc.ShareInfoCtr1 shareInfoCtr1 = new srvsvc.ShareInfoCtr1();
        shareInfoCtr1.count = 1;
        shareInfoCtr1.array = new srvsvc.ShareInfo1[] { shareInfo };

        // Inject the ShareInfoCtr1 using reflection
        Field infoField = srvsvc.ShareEnumAll.class.getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(msrpcShareEnum, shareInfoCtr1);

        // Test getEntries method
        FileEntry[] entries = msrpcShareEnum.getEntries();

        assertNotNull(entries);
        assertEquals(1, entries.length);
        
        FileEntry entry = entries[0];
        assertNotNull(entry);
        assertEquals("SingleShare", entry.getName());
        assertEquals(8, entry.getType()); // TYPE_SHARE constant
    }

    @Test
    void testMsrpcShareInfo1ConstructorAndGetters() throws Exception {
        // Create a ShareInfo1 object
        srvsvc.ShareInfo1 shareInfo1 = new srvsvc.ShareInfo1();
        shareInfo1.netname = "TestShare";
        shareInfo1.type = 0;
        shareInfo1.remark = "Test remark";

        // Test MsrpcShareInfo1 inner class
        MsrpcShareEnum.MsrpcShareInfo1 msrpcShareInfo1 = 
            new MsrpcShareEnum(TEST_SERVER_NAME).new MsrpcShareInfo1(shareInfo1);

        assertNotNull(msrpcShareInfo1);
        assertEquals("TestShare", msrpcShareInfo1.getName());
        assertEquals(8, msrpcShareInfo1.getType()); // TYPE_SHARE constant
        
        // Verify remark field
        Field remarkField = SmbShareInfo.class.getDeclaredField("remark");
        remarkField.setAccessible(true);
        assertEquals("Test remark", remarkField.get(msrpcShareInfo1));
    }

    @Test
    void testLevelParameter() throws Exception {
        // Verify that level is set to 1 as per the constructor
        Field levelField = srvsvc.ShareEnumAll.class.getDeclaredField("level");
        levelField.setAccessible(true);
        int level = (int) levelField.get(msrpcShareEnum);
        assertEquals(1, level);
    }

    @Test
    void testShareTypeTransformation() throws Exception {
        // Test different share types and their transformations
        // Type 0 (disk share) -> TYPE_SHARE (8)
        srvsvc.ShareInfo1 diskShare = new srvsvc.ShareInfo1();
        diskShare.netname = "DiskShare";
        diskShare.type = 0;
        diskShare.remark = "Disk share";

        // Type 1 (printer share) -> TYPE_PRINTER (4)
        srvsvc.ShareInfo1 printerShare = new srvsvc.ShareInfo1();
        printerShare.netname = "PrinterShare";
        printerShare.type = 1;
        printerShare.remark = "Printer share";

        // Type 3 (named pipe) -> TYPE_NAMED_PIPE (16)
        srvsvc.ShareInfo1 pipeShare = new srvsvc.ShareInfo1();
        pipeShare.netname = "PipeShare";
        pipeShare.type = 3;
        pipeShare.remark = "Named pipe";

        // Create ShareInfoCtr1 with different share types
        srvsvc.ShareInfoCtr1 shareInfoCtr1 = new srvsvc.ShareInfoCtr1();
        shareInfoCtr1.count = 3;
        shareInfoCtr1.array = new srvsvc.ShareInfo1[] { diskShare, printerShare, pipeShare };

        // Inject the ShareInfoCtr1 using reflection
        Field infoField = srvsvc.ShareEnumAll.class.getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(msrpcShareEnum, shareInfoCtr1);

        // Test getEntries method
        FileEntry[] entries = msrpcShareEnum.getEntries();

        assertNotNull(entries);
        assertEquals(3, entries.length);

        // Verify disk share
        assertEquals("DiskShare", entries[0].getName());
        assertEquals(8, entries[0].getType()); // TYPE_SHARE

        // Verify printer share
        assertEquals("PrinterShare", entries[1].getName());
        assertEquals(32, entries[1].getType()); // TYPE_PRINTER (0x20)

        // Verify named pipe
        assertEquals("PipeShare", entries[2].getName());
        assertEquals(16, entries[2].getType()); // TYPE_NAMED_PIPE
    }
}