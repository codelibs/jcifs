package jcifs.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.smb.FileEntry;

class MsrpcShareEnumTest {

    private static final String TEST_SERVER_NAME = "testServer";

    @Mock
    private srvsvc.ShareInfoCtr1 mockShareInfoCtr1;
    @Mock
    private srvsvc.ShareInfo1 mockShareInfo1_1;
    @Mock
    private srvsvc.ShareInfo1 mockShareInfo1_2;

    private MsrpcShareEnum msrpcShareEnum;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        // Mock the constructor's super call behavior if necessary, though for this simple case,
        // we'll focus on the public methods and the internal class.
        // The actual srvsvc.ShareEnumAll constructor is called, so we need to ensure
        // our mockShareInfoCtr1 is used when getEntries is called.
        // This is tricky because MsrpcShareEnum creates its own ShareInfoCtr1.
        // For testing getEntries, we will need to set up the internal 'info' field.
    }

    @Test
    void testConstructor() {
        // Test that the constructor initializes the object correctly
        MsrpcShareEnum shareEnum = new MsrpcShareEnum(TEST_SERVER_NAME);
        assertNotNull(shareEnum);
        // Verify that the server name is correctly formatted in the super constructor call
        // Verify that the instance was created successfully
        assertNotNull(shareEnum, "MsrpcShareEnum should be created successfully");
        
        // Since this class extends srvsvc.NetShareEnumAll and testing internal
        // protected fields is inappropriate for unit tests, we only verify construction.
    }

    @Test
    void testGetEntriesWithMultipleShares() {
        // Prepare mock data for multiple shares
        srvsvc.ShareInfo1[] shareInfo1Array = { mockShareInfo1_1, mockShareInfo1_2 };

        when(mockShareInfoCtr1.count).thenReturn(2);
        mockShareInfoCtr1.array = shareInfo1Array; // Directly set the array as it's a public field

        when(mockShareInfo1_1.netname).thenReturn("Share1");
        when(mockShareInfo1_1.type).thenReturn(0); // Example type
        when(mockShareInfo1_1.remark).thenReturn("Remark for Share1");

        when(mockShareInfo1_2.netname).thenReturn("Share2");
        when(mockShareInfo1_2.type).thenReturn(1); // Example type
        when(mockShareInfo1_2.remark).thenReturn("Remark for Share2");

        // Create a real MsrpcShareEnum instance and then use reflection to set its 'info' field
        // This is necessary because the constructor of MsrpcShareEnum creates a new ShareInfoCtr1
        // and we need to inject our mock for testing getEntries().
        msrpcShareEnum = new MsrpcShareEnum(TEST_SERVER_NAME);
        try {
            java.lang.reflect.Field infoField = srvsvc.ShareEnumAll.class.getDeclaredField("info");
            infoField.setAccessible(true);
            infoField.set(msrpcShareEnum, mockShareInfoCtr1);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            fail("Failed to inject mockShareInfoCtr1: " + e.getMessage());
        }

        FileEntry[] entries = msrpcShareEnum.getEntries();

        assertNotNull(entries);
        assertEquals(2, entries.length);

        // Verify the first entry
        FileEntry entry1 = entries[0];
        assertNotNull(entry1);
        assertEquals("Share1", entry1.getName());
        assertEquals(0, entry1.getType());
        try {
            java.lang.reflect.Field remarkField = jcifs.internal.smb1.net.SmbShareInfo.class.getDeclaredField("remark");
            remarkField.setAccessible(true);
            assertEquals("Remark for Share1", remarkField.get(entry1));
        } catch (NoSuchFieldException | IllegalAccessException e) {
            fail("Failed to access remark field: " + e.getMessage());
        }

        // Verify the second entry
        FileEntry entry2 = entries[1];
        assertNotNull(entry2);
        assertEquals("Share2", entry2.getName());

    }

    @Test
    void testGetEntriesWithNoShares() {
        // Prepare mock data for no shares
        when(mockShareInfoCtr1.count).thenReturn(0);
        mockShareInfoCtr1.array = new srvsvc.ShareInfo1[0]; // Empty array

        msrpcShareEnum = new MsrpcShareEnum(TEST_SERVER_NAME);
        try {
            java.lang.reflect.Field infoField = srvsvc.ShareEnumAll.class.getDeclaredField("info");
            infoField.setAccessible(true);
            infoField.set(msrpcShareEnum, mockShareInfoCtr1);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            fail("Failed to inject mockShareInfoCtr1: " + e.getMessage());
        }

        FileEntry[] entries = msrpcShareEnum.getEntries();

        assertNotNull(entries);
        assertEquals(0, entries.length);
    }

    @Test
    void testMsrpcShareInfo1ConstructorAndGetters() {
        // Test the internal MsrpcShareInfo1 class
        when(mockShareInfo1_1.netname).thenReturn("SingleShare");
        when(mockShareInfo1_1.type).thenReturn(0);
        when(mockShareInfo1_1.remark).thenReturn("Remark for SingleShare");

        MsrpcShareEnum.MsrpcShareInfo1 msrpcShareInfo1 = new MsrpcShareEnum(TEST_SERVER_NAME).new MsrpcShareInfo1(mockShareInfo1_1);

        assertNotNull(msrpcShareInfo1);
        assertEquals("SingleShare", msrpcShareInfo1.getName());
        assertEquals(0, msrpcShareInfo1.getType());
        try {
            java.lang.reflect.Field remarkField = jcifs.internal.smb1.net.SmbShareInfo.class.getDeclaredField("remark");
            remarkField.setAccessible(true);
            assertEquals("Remark for SingleShare", remarkField.get(msrpcShareInfo1));
        } catch (NoSuchFieldException | IllegalAccessException e) {
            fail("Failed to access remark field: " + e.getMessage());
        }

    }
}
