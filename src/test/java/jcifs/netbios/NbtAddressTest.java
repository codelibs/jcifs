package jcifs.netbios;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.InetAddress;
import java.net.UnknownHostException;

import jcifs.netbios.UniAddress;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.NameServiceClient;
import jcifs.NetbiosAddress;

@ExtendWith(MockitoExtension.class)
class NbtAddressTest {

    @Mock
    private Name mockName;
    @Mock
    private CIFSContext mockContext;
    @Mock
    private NameServiceClient mockNameServiceClient;

    private int testAddressInt = 0xC0A80101; // 192.168.1.1
    private byte[] testMacAddress = new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };

    @BeforeEach
    void setUp() {
        // Common setup for mocks
        when(mockContext.getNameServiceClient()).thenReturn(mockNameServiceClient);
    }

    @Test
    void testConstructorWithMinimalParameters() throws UnknownHostException {
        // Test the constructor with minimal parameters
        when(mockName.getName()).thenReturn("TESTHOST");
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);

        assertNotNull(nbtAddress);
        assertEquals("TESTHOST", nbtAddress.getHostName());
        assertArrayEquals(new byte[] { (byte) 192, (byte) 168, (byte) 1, (byte) 1 }, nbtAddress.getAddress());
        assertFalse(nbtAddress.isGroupAddress(mockContext)); // Requires checkData, will mock later
        assertEquals(NbtAddress.H_NODE, nbtAddress.getNodeType(mockContext)); // Requires checkData, will mock later
    }

    @Test
    void testConstructorWithAllParameters() throws UnknownHostException {
        // Test the constructor with all parameters
        when(mockName.getName()).thenReturn("FULLHOST");
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, true, NbtAddress.B_NODE, true, true, false, true, testMacAddress);

        assertNotNull(nbtAddress);
        assertEquals("FULLHOST", nbtAddress.getHostName());
        assertArrayEquals(new byte[] { (byte) 192, (byte) 168, (byte) 1, (byte) 1 }, nbtAddress.getAddress());
        assertTrue(nbtAddress.isGroupAddress(mockContext)); // Requires checkData, will mock later
        assertEquals(NbtAddress.B_NODE, nbtAddress.getNodeType(mockContext)); // Requires checkData, will mock later
        assertTrue(nbtAddress.isBeingDeleted(mockContext)); // Requires checkNodeStatusData, will mock later
        assertTrue(nbtAddress.isInConflict(mockContext)); // Requires checkNodeStatusData, will mock later
        assertFalse(nbtAddress.isActive(mockContext)); // Requires checkNodeStatusData, will mock later
        assertTrue(nbtAddress.isPermanent(mockContext)); // Requires checkNodeStatusData, will mock later
        assertArrayEquals(testMacAddress, nbtAddress.getMacAddress(mockContext)); // Requires checkNodeStatusData, will mock later
    }

    @Test
    void testUnwrap() {
        // Test unwrap method for correct type casting
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        NbtAddress unwrapped = nbtAddress.unwrap(NbtAddress.class);
        assertNotNull(unwrapped);
        assertSame(nbtAddress, unwrapped);

        // Test unwrap for incompatible type (UniAddress is another Address type)
        assertNull(nbtAddress.unwrap(UniAddress.class));
    }

    @Test
    void testFirstCalledName_RegularHostName() {
        // Test firstCalledName with a regular hostname
        when(mockName.getName()).thenReturn("MYSERVER");
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertEquals("MYSERVER", nbtAddress.firstCalledName());
    }

    @Test
    void testFirstCalledName_IpAddress() {
        // Test firstCalledName with an IP address string
        when(mockName.getName()).thenReturn("192.168.1.100");
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertEquals(NbtAddress.SMBSERVER_NAME, nbtAddress.firstCalledName());
    }

    @Test
    void testFirstCalledName_SpecialHexCode() {
        // Test firstCalledName with special hex codes
        when(mockName.getName()).thenReturn("DOMAIN");
        mockName.hexCode = 0x1B; // Domain Master Browser
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertEquals(NbtAddress.SMBSERVER_NAME, nbtAddress.firstCalledName());

        mockName.hexCode = 0x1C; // Domain Controller
        nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertEquals(NbtAddress.SMBSERVER_NAME, nbtAddress.firstCalledName());

        mockName.hexCode = 0x1D; // Master Browser
        nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertEquals(NbtAddress.SMBSERVER_NAME, nbtAddress.firstCalledName());
    }

    @Test
    void testNextCalledName_InitialCall() {
        // Test nextCalledName when calledName is hostName.name initially
        when(mockName.getName()).thenReturn("MYSERVER");
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        nbtAddress.firstCalledName(); // Initialize calledName
        assertEquals(NbtAddress.SMBSERVER_NAME, nbtAddress.nextCalledName(mockContext));
    }

    @Test
    void testNextCalledName_SmbServerName_NameType0x1D() throws UnknownHostException {
        // Test nextCalledName when calledName is SMBSERVER_NAME and nameType is 0x1D
        when(mockName.getName()).thenReturn("MASTERBROWSER");
        mockName.hexCode = 0x1D;
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        nbtAddress.firstCalledName(); // Initialize calledName to SMBSERVER_NAME

        NetbiosAddress mockNetbiosAddress20 = mock(NetbiosAddress.class);
        when(mockNetbiosAddress20.getNameType()).thenReturn(0x20);
        when(mockNetbiosAddress20.getHostName()).thenReturn("ACTUAL_SERVER_NAME");

        NetbiosAddress[] nodeStatusResponse = { mock(NetbiosAddress.class), mockNetbiosAddress20 };
        when(mockNameServiceClient.getNodeStatus(nbtAddress)).thenReturn(nodeStatusResponse);

        nbtAddress.calledName = NbtAddress.SMBSERVER_NAME; // Manually set for this test case
        assertEquals("ACTUAL_SERVER_NAME", nbtAddress.nextCalledName(mockContext));
        verify(mockNameServiceClient).getNodeStatus(nbtAddress);
    }

    @Test
    void testNextCalledName_SmbServerName_DataFromNodeStatus() throws UnknownHostException {
        // Test nextCalledName when calledName is SMBSERVER_NAME and isDataFromNodeStatus is true
        when(mockName.getName()).thenReturn("HOST");
        NbtAddress nbtAddress =
                new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE, false, false, false, false, testMacAddress); // isDataFromNodeStatus is true by constructor

        nbtAddress.calledName = NbtAddress.SMBSERVER_NAME; // Manually set for this test case
        when(mockNameServiceClient.getNodeStatus(nbtAddress)).thenReturn(new NetbiosAddress[] {}); // Mock empty response
        assertEquals("HOST", nbtAddress.nextCalledName(mockContext));
        verify(mockNameServiceClient).getNodeStatus(nbtAddress);
    }

    @Test
    void testNextCalledName_SmbServerName_UnknownHostException() throws UnknownHostException {
        // Test nextCalledName when getNodeStatus throws UnknownHostException
        when(mockName.getName()).thenReturn("HOST");
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        nbtAddress.calledName = NbtAddress.SMBSERVER_NAME; // Manually set for this test case

        doThrow(new UnknownHostException()).when(mockNameServiceClient).getNodeStatus(nbtAddress);

        assertNull(nbtAddress.nextCalledName(mockContext));
        verify(mockNameServiceClient).getNodeStatus(nbtAddress);
    }

    @Test
    void testNextCalledName_OtherCases() {
        // Test nextCalledName for other cases where calledName is not hostName.name or SMBSERVER_NAME
        when(mockName.getName()).thenReturn("HOST");
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        nbtAddress.calledName = "SOME_OTHER_NAME"; // Manually set for this test case
        assertNull(nbtAddress.nextCalledName(mockContext));
    }

    @Test
    void testGetHostName_KnownHost() {
        // Test getHostName when hostname is known
        when(mockName.isUnknown()).thenReturn(false);
        when(mockName.getName()).thenReturn("KNOWNHOST");
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertEquals("KNOWNHOST", nbtAddress.getHostName());
    }

    @Test
    void testGetHostName_UnknownHost() {
        // Test getHostName when hostname is unknown, should return IP address
        when(mockName.isUnknown()).thenReturn(true);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertEquals("192.168.1.1", nbtAddress.getHostAddress());
        assertEquals("192.168.1.1", nbtAddress.getHostName());
    }

    @Test
    void testGetName() {
        // Test getName method
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertSame(mockName, nbtAddress.getName());
    }

    @Test
    void testGetAddress() {
        // Test getAddress for correct byte array conversion
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertArrayEquals(new byte[] { (byte) 192, (byte) 168, (byte) 1, (byte) 1 }, nbtAddress.getAddress());
    }

    @Test
    void testGetInetAddress() throws UnknownHostException {
        // Test getInetAddress for correct InetAddress creation
        when(mockName.isUnknown()).thenReturn(false);
        when(mockName.getName()).thenReturn("TESTHOST");
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        InetAddress expectedInetAddress = InetAddress.getByName("192.168.1.1");
        assertEquals(expectedInetAddress, nbtAddress.getInetAddress());
    }

    @Test
    void testToInetAddress() throws UnknownHostException {
        // Test toInetAddress (delegates to getInetAddress)
        when(mockName.isUnknown()).thenReturn(false);
        when(mockName.getName()).thenReturn("TESTHOST");
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        InetAddress expectedInetAddress = InetAddress.getByName("192.168.1.1");
        assertEquals(expectedInetAddress, nbtAddress.toInetAddress());
    }

    @Test
    void testGetHostAddress() {
        // Test getHostAddress for correct string format
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertEquals("192.168.1.1", nbtAddress.getHostAddress());
    }

    @Test
    void testGetNameType() {
        // Test getNameType
        mockName.hexCode = 0x20; // Example hex code
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertEquals(0x20, nbtAddress.getNameType());
    }

    @Test
    void testHashCode() {
        // Test hashCode consistency
        NbtAddress nbtAddress1 = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        NbtAddress nbtAddress2 = new NbtAddress(mock(Name.class), testAddressInt, true, NbtAddress.B_NODE); // Different name, group, nodeType
        assertEquals(nbtAddress1.hashCode(), nbtAddress2.hashCode());
        assertEquals(testAddressInt, nbtAddress1.hashCode());
    }

    @Test
    void testEquals() {
        // Test equals method
        NbtAddress nbtAddress1 = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        NbtAddress nbtAddress2 = new NbtAddress(mock(Name.class), testAddressInt, true, NbtAddress.B_NODE); // Same address, different other fields
        NbtAddress nbtAddress3 = new NbtAddress(mock(Name.class), 0xC0A80102, false, NbtAddress.H_NODE); // Different address

        assertTrue(nbtAddress1.equals(nbtAddress2)); // Should be true as only address is compared
        assertFalse(nbtAddress1.equals(nbtAddress3));
        assertFalse(nbtAddress1.equals(null));
        assertFalse(nbtAddress1.equals("some string"));
    }

    @Test
    void testToString() {
        // Test toString method
        when(mockName.toString()).thenReturn("TESTHOST<00>");
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertEquals("TESTHOST<00>/192.168.1.1", nbtAddress.toString());
    }

    // Tests for methods that call checkData(CIFSContext tc)
    @Test
    void testIsGroupAddress_CheckDataCalled() throws UnknownHostException {
        // Test isGroupAddress when checkData is called (hostName is unknown)
        when(mockName.isUnknown()).thenReturn(true);
        doNothing().when(mockNameServiceClient).getNbtAllByAddress(any(NbtAddress.class)); // Mock the call

        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, true, NbtAddress.H_NODE);
        assertTrue(nbtAddress.isGroupAddress(mockContext));
        verify(mockNameServiceClient).getNbtAllByAddress(nbtAddress);
    }

    @Test
    void testIsGroupAddress_NoCheckDataCall() throws UnknownHostException {
        // Test isGroupAddress when checkData is NOT called (hostName is known)
        when(mockName.isUnknown()).thenReturn(false);
        when(mockName.getName()).thenReturn("KNOWNHOST");

        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertFalse(nbtAddress.isGroupAddress(mockContext));
        verify(mockNameServiceClient, never()).getNbtAllByAddress(any(NbtAddress.class));
    }

    @Test
    void testGetNodeType_CheckDataCalled() throws UnknownHostException {
        // Test getNodeType when checkData is called (hostName is unknown)
        when(mockName.isUnknown()).thenReturn(true);
        doNothing().when(mockNameServiceClient).getNbtAllByAddress(any(NbtAddress.class));

        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.P_NODE);
        assertEquals(NbtAddress.P_NODE, nbtAddress.getNodeType(mockContext));
        verify(mockNameServiceClient).getNbtAllByAddress(nbtAddress);
    }

    // Tests for methods that call checkNodeStatusData(CIFSContext tc)
    @Test
    void testIsBeingDeleted_CheckNodeStatusDataCalled() throws UnknownHostException {
        // Test isBeingDeleted when checkNodeStatusData is called (isDataFromNodeStatus is false)
        when(mockName.getName()).thenReturn("HOST");
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE); // isDataFromNodeStatus is false by default constructor
        doNothing().when(mockNameServiceClient).getNbtAllByAddress(any(NbtAddress.class));

        assertFalse(nbtAddress.isBeingDeleted(mockContext)); // Default value before update
        verify(mockNameServiceClient).getNbtAllByAddress(nbtAddress);
    }

    @Test
    void testIsBeingDeleted_NoCheckNodeStatusDataCall() throws UnknownHostException {
        // Test isBeingDeleted when checkNodeStatusData is NOT called (isDataFromNodeStatus is true)
        when(mockName.getName()).thenReturn("HOST");
        NbtAddress nbtAddress =
                new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE, true, false, false, false, testMacAddress); // isDataFromNodeStatus is true by constructor

        assertTrue(nbtAddress.isBeingDeleted(mockContext));
        verify(mockNameServiceClient, never()).getNbtAllByAddress(any(NbtAddress.class));
    }

    @Test
    void testIsInConflict_CheckNodeStatusDataCalled() throws UnknownHostException {
        // Test isInConflict when checkNodeStatusData is called
        when(mockName.getName()).thenReturn("HOST");
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        doNothing().when(mockNameServiceClient).getNbtAllByAddress(any(NbtAddress.class));

        assertFalse(nbtAddress.isInConflict(mockContext));
        verify(mockNameServiceClient).getNbtAllByAddress(nbtAddress);
    }

    @Test
    void testIsActive_CheckNodeStatusDataCalled() throws UnknownHostException {
        // Test isActive when checkNodeStatusData is called
        when(mockName.getName()).thenReturn("HOST");
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        doNothing().when(mockNameServiceClient).getNbtAllByAddress(any(NbtAddress.class));

        assertFalse(nbtAddress.isActive(mockContext));
        verify(mockNameServiceClient).getNbtAllByAddress(nbtAddress);
    }

    @Test
    void testIsPermanent_CheckNodeStatusDataCalled() throws UnknownHostException {
        // Test isPermanent when checkNodeStatusData is called
        when(mockName.getName()).thenReturn("HOST");
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        doNothing().when(mockNameServiceClient).getNbtAllByAddress(any(NbtAddress.class));

        assertFalse(nbtAddress.isPermanent(mockContext));
        verify(mockNameServiceClient).getNbtAllByAddress(nbtAddress);
    }

    @Test
    void testGetMacAddress_CheckNodeStatusDataCalled() throws UnknownHostException {
        // Test getMacAddress when checkNodeStatusData is called
        when(mockName.getName()).thenReturn("HOST");
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        doNothing().when(mockNameServiceClient).getNbtAllByAddress(any(NbtAddress.class));

        assertNull(nbtAddress.getMacAddress(mockContext)); // Default value before update
        verify(mockNameServiceClient).getNbtAllByAddress(nbtAddress);
    }

    @Test
    void testConstants() {
        // Test public static final constants
        assertEquals("*\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000",
                NbtAddress.ANY_HOSTS_NAME);
        assertEquals("\u0001\u0002__MSBROWSE__\u0002", NbtAddress.MASTER_BROWSER_NAME);
        assertEquals("*SMBSERVER     ", NbtAddress.SMBSERVER_NAME);
        assertEquals(0, NbtAddress.B_NODE);
        assertEquals(1, NbtAddress.P_NODE);
        assertEquals(2, NbtAddress.M_NODE);
        assertEquals(3, NbtAddress.H_NODE);
        assertArrayEquals(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, NbtAddress.UNKNOWN_MAC_ADDRESS);
    }
}
