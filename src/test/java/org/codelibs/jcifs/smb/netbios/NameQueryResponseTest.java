package org.codelibs.jcifs.smb.netbios;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;

import java.lang.reflect.Field;

import org.codelibs.jcifs.smb.Configuration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class NameQueryResponseTest {

    @Mock
    private Configuration mockConfig;

    private NameQueryResponse nameQueryResponse;

    @BeforeEach
    void setUp() {
        // Mock the OEM encoding configuration with lenient stubbing
        // since not all tests need this stub
        lenient().when(mockConfig.getOemEncoding()).thenReturn("UTF-8");

        // Initialize NameQueryResponse before each test
        nameQueryResponse = new NameQueryResponse(mockConfig);
    }

    @Test
    void constructor_shouldInitializeRecordName() throws NoSuchFieldException, IllegalAccessException {
        // Verify that the 'recordName' field in the superclass (NameServicePacket) is initialized
        Field recordNameField = NameServicePacket.class.getDeclaredField("recordName");
        recordNameField.setAccessible(true); // Allow access to protected field
        Name recordName = (Name) recordNameField.get(nameQueryResponse);
        assertNotNull(recordName, "recordName should be initialized by the constructor");
    }

    @Test
    void writeBodyWireFormat_shouldReturnZero() {
        // This method is implemented to always return 0
        byte[] dst = new byte[10];
        int dstIndex = 0;
        assertEquals(0, nameQueryResponse.writeBodyWireFormat(dst, dstIndex), "writeBodyWireFormat should always return 0");
    }

    @Test
    void readBodyWireFormat_shouldCallReadResourceRecordWireFormat() throws NoSuchFieldException, IllegalAccessException {
        // This method directly calls a superclass method (readResourceRecordWireFormat).
        // We need to setup fields to avoid NPE when parsing

        // Set recordName for parsing
        Field recordNameField = NameServicePacket.class.getDeclaredField("recordName");
        recordNameField.setAccessible(true);
        Name mockRecordName = new Name(mockConfig);
        recordNameField.set(nameQueryResponse, mockRecordName);

        // Prepare a byte array with valid NetBIOS name format
        byte[] src = new byte[100];
        int srcIndex = 0;

        // Start with compressed name pointer (0xC0) to use questionName
        src[srcIndex] = (byte) 0xC0;
        src[srcIndex + 1] = 0x0C; // Pointer offset
        // recordType (2 bytes)
        src[srcIndex + 2] = 0x00;
        src[srcIndex + 3] = 0x20; // NB (0x0020)
        // recordClass (2 bytes)
        src[srcIndex + 4] = 0x00;
        src[srcIndex + 5] = 0x01; // IN (0x0001)
        // ttl (4 bytes)
        src[srcIndex + 6] = 0x00;
        src[srcIndex + 7] = 0x00;
        src[srcIndex + 8] = 0x00;
        src[srcIndex + 9] = 0x00;
        // rDataLength (2 bytes)
        src[srcIndex + 10] = 0x00;
        src[srcIndex + 11] = 0x06; // 6 bytes of data

        // Initialize questionName to avoid NPE
        Field questionNameField = NameServicePacket.class.getDeclaredField("questionName");
        questionNameField.setAccessible(true);
        questionNameField.set(nameQueryResponse, mockRecordName);

        // The method should return the number of bytes read by readResourceRecordWireFormat
        int result = nameQueryResponse.readBodyWireFormat(src, srcIndex);
        assertEquals(12 + 6, result, "readBodyWireFormat should return the total bytes read");
    }

    @Test
    void writeRDataWireFormat_shouldReturnZero() {
        // This method is implemented to always return 0
        byte[] dst = new byte[10];
        int dstIndex = 0;
        assertEquals(0, nameQueryResponse.writeRDataWireFormat(dst, dstIndex), "writeRDataWireFormat should always return 0");
    }

    @Test
    void readRDataWireFormat_shouldReturnZero_whenResultCodeIsNotZero() throws NoSuchFieldException, IllegalAccessException {
        // Set 'resultCode' field in superclass to a non-zero value
        Field resultCodeField = NameServicePacket.class.getDeclaredField("resultCode");
        resultCodeField.setAccessible(true);
        resultCodeField.set(nameQueryResponse, 1); // Simulate an error result code

        byte[] src = new byte[10];
        int srcIndex = 0;
        assertEquals(0, nameQueryResponse.readRDataWireFormat(src, srcIndex), "readRDataWireFormat should return 0 if resultCode is not 0");
    }

    @Test
    void readRDataWireFormat_shouldReturnZero_whenOpCodeIsNotQuery() throws NoSuchFieldException, IllegalAccessException {
        // Set 'opCode' field in superclass to a value other than QUERY (0)
        Field opCodeField = NameServicePacket.class.getDeclaredField("opCode");
        opCodeField.setAccessible(true);
        opCodeField.set(nameQueryResponse, 7); // WACK opCode, which is not QUERY (0)

        // Ensure 'resultCode' is 0 for this test to isolate opCode condition
        Field resultCodeField = NameServicePacket.class.getDeclaredField("resultCode");
        resultCodeField.setAccessible(true);
        resultCodeField.set(nameQueryResponse, 0);

        // Initialize addrEntry to avoid NPE
        Field addrEntryField = NameServicePacket.class.getDeclaredField("addrEntry");
        addrEntryField.setAccessible(true);
        addrEntryField.set(nameQueryResponse, new NbtAddress[1]);

        byte[] src = new byte[10];
        int srcIndex = 0;
        assertEquals(0, nameQueryResponse.readRDataWireFormat(src, srcIndex), "readRDataWireFormat should return 0 if opCode is not QUERY");
    }

    @Test
    void readRDataWireFormat_shouldSetNbtAddress_whenAddressIsNonZero_groupNameFalse_nodeTypeZero()
            throws NoSuchFieldException, IllegalAccessException {
        // Prepare superclass fields for successful parsing
        setSuperclassFieldsForSuccessfulParsing();

        byte[] src = new byte[10];
        int srcIndex = 0;

        // Simulate groupName = false (0x00), nodeType = 0 (0x00) -> src[srcIndex] = 0x00
        src[srcIndex] = (byte) 0x00;
        src[srcIndex + 1] = (byte) 0x00; // Reserved/padding byte

        // Simulate address = 192.168.1.1 (0xC0A80101)
        src[srcIndex + 2] = (byte) 0xC0;
        src[srcIndex + 3] = (byte) 0xA8;
        src[srcIndex + 4] = (byte) 0x01;
        src[srcIndex + 5] = (byte) 0x01;

        // Set 'addrEntry' and 'addrIndex' fields in superclass for the response to be stored
        Field addrEntryField = NameServicePacket.class.getDeclaredField("addrEntry");
        addrEntryField.setAccessible(true);
        addrEntryField.set(nameQueryResponse, new NbtAddress[1]);

        Field addrIndexField = NameServicePacket.class.getDeclaredField("addrIndex");
        addrIndexField.setAccessible(true);
        addrIndexField.set(nameQueryResponse, 0);

        // Set 'recordName' for NbtAddress constructor
        Field recordNameField = NameServicePacket.class.getDeclaredField("recordName");
        recordNameField.setAccessible(true);
        Name mockRecordName = new Name(mockConfig);
        recordNameField.set(nameQueryResponse, mockRecordName);

        assertEquals(6, nameQueryResponse.readRDataWireFormat(src, srcIndex), "readRDataWireFormat should return 6 for successful parsing");

        NbtAddress[] addrEntry = (NbtAddress[]) addrEntryField.get(nameQueryResponse);
        assertNotNull(addrEntry[0], "NbtAddress should be created when address is non-zero");
        byte[] nodeAddress = addrEntry[0].getAddress();
        assertNotNull(nodeAddress, "Node address should not be null");
        // Note: Cannot test isGroupAddress() and getNodeType() without CIFSContext in unit test
        // These methods require network operations and are integration test material
    }

    @Test
    void readRDataWireFormat_shouldSetNbtAddress_whenAddressIsNonZero_groupNameTrue_nodeTypeNonZero()
            throws NoSuchFieldException, IllegalAccessException {
        // Prepare superclass fields for successful parsing
        setSuperclassFieldsForSuccessfulParsing();

        byte[] src = new byte[10];
        int srcIndex = 0;

        // Simulate groupName = true (0x80), nodeType = 1 (0x20) -> src[srcIndex] = 0xA0
        src[srcIndex] = (byte) 0xA0;
        src[srcIndex + 1] = (byte) 0x00; // Reserved/padding byte

        // Simulate address = 10.0.0.5 (0x0A000005)
        src[srcIndex + 2] = (byte) 0x0A;
        src[srcIndex + 3] = (byte) 0x00;
        src[srcIndex + 4] = (byte) 0x00;
        src[srcIndex + 5] = (byte) 0x05;

        // Set 'addrEntry' and 'addrIndex' fields in superclass
        Field addrEntryField = NameServicePacket.class.getDeclaredField("addrEntry");
        addrEntryField.setAccessible(true);
        addrEntryField.set(nameQueryResponse, new NbtAddress[1]);

        Field addrIndexField = NameServicePacket.class.getDeclaredField("addrIndex");
        addrIndexField.setAccessible(true);
        addrIndexField.set(nameQueryResponse, 0);

        // Set 'recordName' for NbtAddress constructor
        Field recordNameField = NameServicePacket.class.getDeclaredField("recordName");
        recordNameField.setAccessible(true);
        Name mockRecordName = new Name(mockConfig);
        recordNameField.set(nameQueryResponse, mockRecordName);

        assertEquals(6, nameQueryResponse.readRDataWireFormat(src, srcIndex), "readRDataWireFormat should return 6 for successful parsing");

        NbtAddress[] addrEntry = (NbtAddress[]) addrEntryField.get(nameQueryResponse);
        assertNotNull(addrEntry[0], "NbtAddress should be created when address is non-zero");
        byte[] nodeAddress = addrEntry[0].getAddress();
        assertNotNull(nodeAddress, "Node address should not be null");
        // Note: Cannot test isGroupAddress() and getNodeType() without CIFSContext in unit test
        // These methods require network operations and are integration test material
    }

    @Test
    void readRDataWireFormat_shouldSetAddrEntryToNull_whenAddressIsZero() throws NoSuchFieldException, IllegalAccessException {
        // Prepare superclass fields for successful parsing
        setSuperclassFieldsForSuccessfulParsing();

        byte[] src = new byte[10];
        int srcIndex = 0;

        // Simulate groupName = false, nodeType = 0
        src[srcIndex] = (byte) 0x00;
        src[srcIndex + 1] = (byte) 0x00;

        // Simulate address = 0.0.0.0
        src[srcIndex + 2] = (byte) 0x00;
        src[srcIndex + 3] = (byte) 0x00;
        src[srcIndex + 4] = (byte) 0x00;
        src[srcIndex + 5] = (byte) 0x00;

        // Set 'addrEntry' and 'addrIndex' fields in superclass
        Field addrEntryField = NameServicePacket.class.getDeclaredField("addrEntry");
        addrEntryField.setAccessible(true);
        addrEntryField.set(nameQueryResponse, new NbtAddress[1]);

        Field addrIndexField = NameServicePacket.class.getDeclaredField("addrIndex");
        addrIndexField.setAccessible(true);
        addrIndexField.set(nameQueryResponse, 0);

        assertEquals(6, nameQueryResponse.readRDataWireFormat(src, srcIndex),
                "readRDataWireFormat should return 6 even if address is zero");

        NbtAddress[] addrEntry = (NbtAddress[]) addrEntryField.get(nameQueryResponse);
        assertNull(addrEntry[0], "NbtAddress should be null when address is zero");
    }

    @Test
    void toString_shouldReturnExpectedFormat_withNullAddrEntry() throws NoSuchFieldException, IllegalAccessException {
        // Set 'addrEntry' field to null for this test case
        Field addrEntryField = NameServicePacket.class.getDeclaredField("addrEntry");
        addrEntryField.setAccessible(true);
        addrEntryField.set(nameQueryResponse, null);

        // The toString method appends to super.toString(). We'll check the appended part.
        String expectedEnd = ",addrEntry=]";
        String actual = nameQueryResponse.toString();
        assertTrue(actual.endsWith(expectedEnd), "toString should end with ',addrEntry=]' when addrEntry is null");
        assertTrue(actual.startsWith("NameQueryResponse["), "toString should start with expected prefix");
    }

    @Test
    void toString_shouldReturnExpectedFormat_withNonNullAddrEntry() throws NoSuchFieldException, IllegalAccessException {
        // Set 'addrEntry' with some NbtAddress objects
        Field addrEntryField = NameServicePacket.class.getDeclaredField("addrEntry");
        addrEntryField.setAccessible(true);

        // Need to set 'recordName' for NbtAddress constructor, as it's used internally by NbtAddress.toString()
        Field recordNameField = NameServicePacket.class.getDeclaredField("recordName");
        recordNameField.setAccessible(true);
        Name mockRecordName = new Name(mockConfig);
        recordNameField.set(nameQueryResponse, mockRecordName);

        NbtAddress[] addresses = new NbtAddress[2];
        // Create dummy NbtAddress objects for testing toString
        addresses[0] = new NbtAddress(mockRecordName, 0xC0A80101, false, 0); // 192.168.1.1
        addresses[1] = new NbtAddress(mockRecordName, 0x0A000005, true, 1); // 10.0.0.5
        addrEntryField.set(nameQueryResponse, addresses);

        String expectedContains = ",addrEntry=[";
        String actual = nameQueryResponse.toString();
        assertTrue(actual.startsWith("NameQueryResponse["), "toString should start with expected prefix");
        assertTrue(actual.contains(expectedContains), "toString should contain the 'addrEntry' part");
        assertTrue(actual.contains("192.168.1.1"), "toString should contain the first NbtAddress string representation");
        assertTrue(actual.contains("10.0.0.5"), "toString should contain the second NbtAddress string representation");
    }

    /**
     * Helper method to set common superclass fields for successful parsing scenarios.
     */
    private void setSuperclassFieldsForSuccessfulParsing() throws NoSuchFieldException, IllegalAccessException {
        Field resultCodeField = NameServicePacket.class.getDeclaredField("resultCode");
        resultCodeField.setAccessible(true);
        resultCodeField.set(nameQueryResponse, 0); // Success result code

        Field opCodeField = NameServicePacket.class.getDeclaredField("opCode");
        opCodeField.setAccessible(true);
        opCodeField.set(nameQueryResponse, NameServicePacket.QUERY); // QUERY opCode
    }
}
