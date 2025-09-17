package org.codelibs.jcifs.smb.netbios;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

import java.lang.reflect.Field;
import java.net.InetAddress;

import org.codelibs.jcifs.smb.Configuration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class NodeStatusResponseTest {

    @Mock
    private Configuration mockConfig;

    @Mock
    private NbtAddress mockQueryAddress;

    private NodeStatusResponse response;

    @BeforeEach
    void setUp() throws Exception {
        // Setup mock configuration with lenient stubbing
        lenient().when(mockConfig.getOemEncoding()).thenReturn("UTF-8");

        // Setup mock query address
        mockQueryAddress = mock(NbtAddress.class);
        Name mockName = new Name(mockConfig, "TEST", 0x20, null);
        mockQueryAddress.hostName = mockName;
        // Convert IP address to int representation for NbtAddress
        InetAddress inetAddr = InetAddress.getByName("192.168.1.100");
        byte[] addrBytes = inetAddr.getAddress();
        mockQueryAddress.address =
                ((addrBytes[0] & 0xFF) << 24) | ((addrBytes[1] & 0xFF) << 16) | ((addrBytes[2] & 0xFF) << 8) | (addrBytes[3] & 0xFF);

        // Create NodeStatusResponse instance
        response = new NodeStatusResponse(mockConfig, mockQueryAddress);
    }

    @Test
    void constructor_shouldInitializeFields() throws Exception {
        // Verify configuration is set
        Field configField = NameServicePacket.class.getDeclaredField("config");
        configField.setAccessible(true);
        assertSame(mockConfig, configField.get(response));

        // Verify queryAddress is set
        Field queryAddressField = NodeStatusResponse.class.getDeclaredField("queryAddress");
        queryAddressField.setAccessible(true);
        assertSame(mockQueryAddress, queryAddressField.get(response));

        // Verify recordName is initialized
        Field recordNameField = NameServicePacket.class.getDeclaredField("recordName");
        recordNameField.setAccessible(true);
        assertNotNull(recordNameField.get(response));

        // Verify macAddress is initialized with correct size
        Field macAddressField = NodeStatusResponse.class.getDeclaredField("macAddress");
        macAddressField.setAccessible(true);
        byte[] macAddress = (byte[]) macAddressField.get(response);
        assertNotNull(macAddress);
        assertEquals(6, macAddress.length);
    }

    @Test
    void writeBodyWireFormat_shouldReturnZero() {
        byte[] dst = new byte[100];
        int result = response.writeBodyWireFormat(dst, 10);
        assertEquals(0, result);
    }

    @Test
    void readBodyWireFormat_shouldDelegateToReadResourceRecordWireFormat() throws Exception {
        // Prepare test data with minimal valid resource record
        byte[] src = new byte[100];
        int srcIndex = 10;

        // Set up a minimal resource record response
        // Name pointer (0xC00C)
        src[srcIndex] = (byte) 0xC0;
        src[srcIndex + 1] = 0x0C;
        // Record type (NBSTAT = 0x0021)
        src[srcIndex + 2] = 0x00;
        src[srcIndex + 3] = 0x21;
        // Record class (IN = 0x0001)
        src[srcIndex + 4] = 0x00;
        src[srcIndex + 5] = 0x01;
        // TTL (4 bytes)
        src[srcIndex + 6] = 0x00;
        src[srcIndex + 7] = 0x00;
        src[srcIndex + 8] = 0x00;
        src[srcIndex + 9] = 0x00;
        // RData length
        src[srcIndex + 10] = 0x00;
        src[srcIndex + 11] = 0x1F; // 31 bytes: 1 + 18 + 6 + 6
        // Number of names (1)
        src[srcIndex + 12] = 0x01;
        // Name entry (18 bytes)
        String name = "TEST            ";
        System.arraycopy(name.getBytes("US-ASCII"), 0, src, srcIndex + 13, 16);
        src[srcIndex + 28] = 0x00; // hex code
        src[srcIndex + 29] = 0x04; // flags
        // MAC address (6 bytes)
        byte[] mac = new byte[6];
        System.arraycopy(mac, 0, src, srcIndex + 31, 6);
        // Stats (6 bytes)
        byte[] stats = new byte[6];
        System.arraycopy(stats, 0, src, srcIndex + 37, 6);

        // Setup recordName and questionName for the test
        Field recordNameField = NameServicePacket.class.getDeclaredField("recordName");
        recordNameField.setAccessible(true);
        recordNameField.set(response, new Name(mockConfig));

        Field questionNameField = NameServicePacket.class.getDeclaredField("questionName");
        questionNameField.setAccessible(true);
        questionNameField.set(response, new Name(mockConfig));

        int result = response.readBodyWireFormat(src, srcIndex);
        assertTrue(result > 0);
    }

    @Test
    void writeRDataWireFormat_shouldReturnZero() {
        byte[] dst = new byte[100];
        int result = response.writeRDataWireFormat(dst, 10);
        assertEquals(0, result);
    }

    @Test
    void readRDataWireFormat_shouldParseNodeStatusData() throws Exception {
        // Prepare test data
        byte[] src = new byte[200];
        int srcIndex = 0;

        // Set rDataLength for the test
        Field rDataLengthField = NameServicePacket.class.getDeclaredField("rDataLength");
        rDataLengthField.setAccessible(true);
        rDataLengthField.set(response, 67); // 1 + 18 * 3 + 6 + 6 = 67 (3 names example)

        // Number of names
        src[srcIndex] = 0x03; // 3 names

        // First name entry (18 bytes)
        String name1 = "WORKSTATION     ";
        System.arraycopy(name1.getBytes("US-ASCII"), 0, src, srcIndex + 1, 16);
        src[srcIndex + 16] = 0x00; // hex code
        src[srcIndex + 17] = 0x04; // flags: active

        // Second name entry (18 bytes)
        String name2 = "DOMAIN          ";
        System.arraycopy(name2.getBytes("US-ASCII"), 0, src, srcIndex + 19, 16);
        src[srcIndex + 34] = 0x00; // hex code
        src[srcIndex + 35] = (byte) 0x84; // flags: group, active

        // Third name entry (18 bytes) - matching queryAddress
        String name3 = "TEST            ";
        System.arraycopy(name3.getBytes("US-ASCII"), 0, src, srcIndex + 37, 16);
        src[srcIndex + 52] = 0x20; // hex code matching mockQueryAddress
        src[srcIndex + 53] = 0x04; // flags: active

        // MAC address (6 bytes)
        byte[] testMac = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
        System.arraycopy(testMac, 0, src, srcIndex + 55, 6);

        // Statistics (6 bytes)
        byte[] stats = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
        System.arraycopy(stats, 0, src, srcIndex + 61, 6);

        int result = response.readRDataWireFormat(src, srcIndex);
        assertEquals(67, result);

        // Verify parsed data
        Field addressArrayField = NodeStatusResponse.class.getDeclaredField("addressArray");
        addressArrayField.setAccessible(true);
        NbtAddress[] addresses = (NbtAddress[]) addressArrayField.get(response);
        assertNotNull(addresses);
        assertEquals(3, addresses.length);

        // Verify MAC address was parsed
        Field macAddressField = NodeStatusResponse.class.getDeclaredField("macAddress");
        macAddressField.setAccessible(true);
        byte[] parsedMac = (byte[]) macAddressField.get(response);
        assertArrayEquals(testMac, parsedMac);

        // Verify stats were parsed
        // Stats length = rDataLength - (numberOfNames * 18) - 1 = 67 - 54 - 1 = 12
        // But MAC address takes 6 bytes, so actual stats length = 12 - 6 = 6
        Field statsField = NodeStatusResponse.class.getDeclaredField("stats");
        statsField.setAccessible(true);
        byte[] parsedStats = (byte[]) statsField.get(response);
        assertEquals(12, parsedStats.length); // 12 bytes total for stats
        // The stats array in NodeStatusResponse contains everything after names
        // MAC is at index 0-5, actual stats at 6-11
        byte[] expectedStats = new byte[12];
        System.arraycopy(testMac, 0, expectedStats, 0, 6); // MAC at beginning
        System.arraycopy(stats, 0, expectedStats, 6, 6); // Stats after MAC
        assertArrayEquals(expectedStats, parsedStats);
    }

    @Test
    void readRDataWireFormat_shouldHandleUnknownQueryAddress() throws Exception {
        // Setup queryAddress with unknown name
        Name unknownName = mock(Name.class);
        lenient().when(unknownName.isUnknown()).thenReturn(true);
        unknownName.hexCode = 0x20;
        unknownName.scope = null;
        mockQueryAddress.hostName = unknownName;

        response = new NodeStatusResponse(mockConfig, mockQueryAddress);

        // Prepare test data
        byte[] src = new byte[100];
        int srcIndex = 0;

        Field rDataLengthField = NameServicePacket.class.getDeclaredField("rDataLength");
        rDataLengthField.setAccessible(true);
        rDataLengthField.set(response, 31); // 1 + 18 + 6 + 6

        // Number of names
        src[srcIndex] = 0x01;

        // Name entry matching unknown query address
        String name = "TEST            ";
        System.arraycopy(name.getBytes("US-ASCII"), 0, src, srcIndex + 1, 16);
        src[srcIndex + 16] = 0x20; // hex code
        src[srcIndex + 17] = 0x04; // flags: active

        // MAC address
        byte[] testMac = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
        System.arraycopy(testMac, 0, src, srcIndex + 19, 6);

        // Statistics
        byte[] stats = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
        System.arraycopy(stats, 0, src, srcIndex + 25, 6);

        int result = response.readRDataWireFormat(src, srcIndex);
        assertEquals(31, result);

        // Verify queryAddress was updated
        assertTrue(mockQueryAddress.isDataFromNodeStatus);
        assertArrayEquals(testMac, mockQueryAddress.macAddress);
    }

    @Test
    void readRDataWireFormat_shouldParseNodeFlags() throws Exception {
        // Prepare test data with various flag combinations
        byte[] src = new byte[100];
        int srcIndex = 0;

        Field rDataLengthField = NameServicePacket.class.getDeclaredField("rDataLength");
        rDataLengthField.setAccessible(true);
        rDataLengthField.set(response, 31); // 1 + 18 + 6 + 6

        // Number of names
        src[srcIndex] = 0x01;

        // Name entry with all flags set
        String name = "TESTFLAGS       ";
        System.arraycopy(name.getBytes("US-ASCII"), 0, src, srcIndex + 1, 16);
        src[srcIndex + 16] = 0x00; // hex code
        src[srcIndex + 17] = (byte) 0xFE; // All flags except one: 11111110
        // Bit 7: group (1)
        // Bits 6-5: owner node type (11 = 3)
        // Bit 4: being deleted (1)
        // Bit 3: in conflict (1)
        // Bit 2: active (1)
        // Bit 1: permanent (1)

        // MAC address
        byte[] testMac = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        System.arraycopy(testMac, 0, src, srcIndex + 19, 6);

        // Statistics
        byte[] stats = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        System.arraycopy(stats, 0, src, srcIndex + 25, 6);

        response.readRDataWireFormat(src, srcIndex);

        // Verify parsed flags
        Field addressArrayField = NodeStatusResponse.class.getDeclaredField("addressArray");
        addressArrayField.setAccessible(true);
        NbtAddress[] addresses = (NbtAddress[]) addressArrayField.get(response);

        NbtAddress addr = addresses[0];
        assertTrue(addr.groupName);
        assertEquals(3, addr.nodeType);
        assertTrue(addr.isBeingDeleted);
        assertTrue(addr.isInConflict);
        assertTrue(addr.isActive);
        assertTrue(addr.isPermanent);
    }

    @Test
    void readRDataWireFormat_shouldHandleMultipleNames() throws Exception {
        // Test with maximum reasonable number of names
        int numNames = 10;
        int dataLength = 1 + (18 * numNames) + 6 + 6;
        byte[] src = new byte[dataLength];
        int srcIndex = 0;

        Field rDataLengthField = NameServicePacket.class.getDeclaredField("rDataLength");
        rDataLengthField.setAccessible(true);
        rDataLengthField.set(response, dataLength);

        // Number of names
        src[srcIndex] = (byte) numNames;

        // Fill in name entries
        for (int i = 0; i < numNames; i++) {
            String name = String.format("NAME%02d          ", i).substring(0, 16);
            System.arraycopy(name.getBytes("US-ASCII"), 0, src, srcIndex + 1 + (i * 18), 16);
            src[srcIndex + 1 + (i * 18) + 15] = (byte) i; // Different hex codes
            src[srcIndex + 1 + (i * 18) + 16] = 0x04; // Active flag
        }

        // MAC address
        int macOffset = srcIndex + 1 + (18 * numNames);
        byte[] testMac = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
        System.arraycopy(testMac, 0, src, macOffset, 6);

        // Statistics
        byte[] stats = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15 };
        System.arraycopy(stats, 0, src, macOffset + 6, 6);

        int result = response.readRDataWireFormat(src, srcIndex);
        assertEquals(dataLength, result);

        // Verify all names were parsed
        Field addressArrayField = NodeStatusResponse.class.getDeclaredField("addressArray");
        addressArrayField.setAccessible(true);
        NbtAddress[] addresses = (NbtAddress[]) addressArrayField.get(response);
        assertEquals(numNames, addresses.length);

        // Verify each address has correct data
        for (int i = 0; i < numNames; i++) {
            assertNotNull(addresses[i]);
            assertTrue(addresses[i].isActive);
            assertFalse(addresses[i].groupName);
        }
    }

    @Test
    void readRDataWireFormat_shouldTrimTrailingSpaces() throws Exception {
        // Test that trailing spaces (0x20) are trimmed from names
        byte[] src = new byte[50];
        int srcIndex = 0;

        Field rDataLengthField = NameServicePacket.class.getDeclaredField("rDataLength");
        rDataLengthField.setAccessible(true);
        rDataLengthField.set(response, 31);

        // Number of names
        src[srcIndex] = 0x01;

        // Name with trailing spaces
        String nameWithSpaces = "COMPUTER";
        byte[] nameBytes = new byte[16];
        System.arraycopy(nameWithSpaces.getBytes("US-ASCII"), 0, nameBytes, 0, nameWithSpaces.length());
        // Fill rest with spaces (0x20)
        for (int i = nameWithSpaces.length(); i < 15; i++) {
            nameBytes[i] = 0x20;
        }
        nameBytes[15] = 0x00; // Last byte for hex code position

        System.arraycopy(nameBytes, 0, src, srcIndex + 1, 16);
        src[srcIndex + 16] = 0x00; // hex code
        src[srcIndex + 17] = 0x04; // active flag

        // MAC and stats
        System.arraycopy(new byte[6], 0, src, srcIndex + 19, 6);
        System.arraycopy(new byte[6], 0, src, srcIndex + 25, 6);

        response.readRDataWireFormat(src, srcIndex);

        Field addressArrayField = NodeStatusResponse.class.getDeclaredField("addressArray");
        addressArrayField.setAccessible(true);
        NbtAddress[] addresses = (NbtAddress[]) addressArrayField.get(response);

        // The name should be trimmed to "COMPUTER" without trailing spaces
        assertEquals("COMPUTER", addresses[0].hostName.name);
    }

    @Test
    void toString_shouldReturnFormattedString() {
        String result = response.toString();
        assertNotNull(result);
        assertTrue(result.startsWith("NodeStatusResponse["));
        assertTrue(result.endsWith("]"));
    }

    @Test
    void readRDataWireFormat_shouldHandleStatsAfterMac() throws Exception {
        // Test with statistics after MAC address
        byte[] src = new byte[50];
        int srcIndex = 0;

        Field rDataLengthField = NameServicePacket.class.getDeclaredField("rDataLength");
        rDataLengthField.setAccessible(true);
        rDataLengthField.set(response, 31); // 1 + 18 + 6 + 6

        // Number of names
        src[srcIndex] = 0x01;

        // Name entry
        String name = "TEST            ";
        System.arraycopy(name.getBytes("US-ASCII"), 0, src, srcIndex + 1, 16);
        src[srcIndex + 16] = 0x00;
        src[srcIndex + 17] = 0x04;

        // MAC address
        byte[] testMac = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
        System.arraycopy(testMac, 0, src, srcIndex + 19, 6);

        // Statistics (6 bytes)
        byte[] testStats = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
        System.arraycopy(testStats, 0, src, srcIndex + 25, 6);

        int result = response.readRDataWireFormat(src, srcIndex);
        assertEquals(31, result);

        // Verify stats array was created with correct size
        // statsLength = rDataLength - (numberOfNames * 18) - 1 = 31 - 18 - 1 = 12
        Field statsField = NodeStatusResponse.class.getDeclaredField("stats");
        statsField.setAccessible(true);
        byte[] parsedStats = (byte[]) statsField.get(response);
        assertNotNull(parsedStats);
        assertEquals(12, parsedStats.length); // Stats array should be 12 bytes
        // The stats array contains everything after names (MAC + actual stats)
        byte[] expectedStats = new byte[12];
        System.arraycopy(testMac, 0, expectedStats, 0, 6); // MAC is at beginning
        System.arraycopy(testStats, 0, expectedStats, 6, 6); // Stats after MAC
        assertArrayEquals(expectedStats, parsedStats);
    }

    @Test
    void readRDataWireFormat_shouldHandleOwnerNodeTypes() throws Exception {
        // Test different owner node types (B-node, P-node, M-node, H-node)
        byte[] src = new byte[200];
        int srcIndex = 0;

        Field rDataLengthField = NameServicePacket.class.getDeclaredField("rDataLength");
        rDataLengthField.setAccessible(true);
        rDataLengthField.set(response, 79); // 1 + 18*4 + 6 + 0

        // Number of names
        src[srcIndex] = 0x04;

        // B-node (00)
        System.arraycopy("BNODE           ".getBytes("US-ASCII"), 0, src, srcIndex + 1, 16);
        src[srcIndex + 16] = 0x00;
        src[srcIndex + 17] = 0x04; // 00000100 - B-node, active

        // P-node (01)
        System.arraycopy("PNODE           ".getBytes("US-ASCII"), 0, src, srcIndex + 19, 16);
        src[srcIndex + 34] = 0x00;
        src[srcIndex + 35] = 0x24; // 00100100 - P-node, active

        // M-node (10)
        System.arraycopy("MNODE           ".getBytes("US-ASCII"), 0, src, srcIndex + 37, 16);
        src[srcIndex + 52] = 0x00;
        src[srcIndex + 53] = 0x44; // 01000100 - M-node, active

        // H-node (11)
        System.arraycopy("HNODE           ".getBytes("US-ASCII"), 0, src, srcIndex + 55, 16);
        src[srcIndex + 70] = 0x00;
        src[srcIndex + 71] = 0x64; // 01100100 - H-node, active

        // MAC address
        System.arraycopy(new byte[6], 0, src, srcIndex + 73, 6);

        response.readRDataWireFormat(src, srcIndex);

        Field addressArrayField = NodeStatusResponse.class.getDeclaredField("addressArray");
        addressArrayField.setAccessible(true);
        NbtAddress[] addresses = (NbtAddress[]) addressArrayField.get(response);

        assertEquals(0, addresses[0].nodeType); // B-node
        assertEquals(1, addresses[1].nodeType); // P-node
        assertEquals(2, addresses[2].nodeType); // M-node
        assertEquals(3, addresses[3].nodeType); // H-node
    }
}