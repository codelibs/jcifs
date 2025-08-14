package jcifs.netbios;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.NameServiceClient;
import jcifs.NetbiosAddress;
import jcifs.config.BaseConfiguration;

@ExtendWith(MockitoExtension.class)
class NbtAddressTest {

    private Name mockName;
    @Mock
    private CIFSContext mockContext;
    @Mock
    private NameServiceClient mockNameServiceClient;
    @Mock
    private BaseConfiguration mockConfig;

    private int testAddressInt = 0xC0A80101; // 192.168.1.1
    private byte[] testMacAddress = new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };

    @BeforeEach
    void setUp() {
        // Setup will be done per test as needed
    }

    @Test
    void testConstructorWithMinimalParameters() throws UnknownHostException {
        // Test the constructor with minimal parameters
        mockName = new Name(mockConfig, "TESTHOST", 0x20, null);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);

        assertNotNull(nbtAddress);
        assertEquals("TESTHOST", nbtAddress.getHostName());
        assertArrayEquals(new byte[] { (byte) 192, (byte) 168, (byte) 1, (byte) 1 }, nbtAddress.getAddress());
        // Don't test isGroupAddress and getNodeType here as they don't need context for known hosts
    }

    @Test
    void testConstructorWithAllParameters() throws UnknownHostException {
        // Test the constructor with all parameters
        mockName = new Name(mockConfig, "FULLHOST", 0x20, null);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, true, NbtAddress.B_NODE, true, true, false, true, testMacAddress);

        assertNotNull(nbtAddress);
        assertEquals("FULLHOST", nbtAddress.getHostName());
        assertArrayEquals(new byte[] { (byte) 192, (byte) 168, (byte) 1, (byte) 1 }, nbtAddress.getAddress());
        // Test the values set by constructor directly when isDataFromNodeStatus is true
        assertTrue(nbtAddress.isGroupAddress(mockContext));
        assertEquals(NbtAddress.B_NODE, nbtAddress.getNodeType(mockContext));
        assertTrue(nbtAddress.isBeingDeleted(mockContext));
        assertTrue(nbtAddress.isInConflict(mockContext));
        assertFalse(nbtAddress.isActive(mockContext));
        assertTrue(nbtAddress.isPermanent(mockContext));
        assertArrayEquals(testMacAddress, nbtAddress.getMacAddress(mockContext));
    }

    @Test
    void testUnwrap() {
        // Test unwrap method for correct type casting
        mockName = new Name(mockConfig, "TEST", 0x20, null);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        NbtAddress unwrapped = nbtAddress.unwrap(NbtAddress.class);
        assertNotNull(unwrapped);
        assertSame(nbtAddress, unwrapped);

        // Test unwrap for incompatible type - NbtAddress implements NetbiosAddress so it should return itself
        NetbiosAddress netbiosUnwrapped = nbtAddress.unwrap(NetbiosAddress.class);
        assertNotNull(netbiosUnwrapped);
        assertSame(nbtAddress, netbiosUnwrapped);

        // Test unwrap for truly incompatible type
        assertNull(nbtAddress.unwrap(UniAddress.class));
    }

    @Test
    void testFirstCalledName_RegularHostName() {
        // Test firstCalledName with a regular hostname
        mockName = new Name(mockConfig, "MYSERVER", 0x20, null);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertEquals("MYSERVER", nbtAddress.firstCalledName());
    }

    @Test
    void testFirstCalledName_IpAddress() {
        // Test firstCalledName with an IP address string
        mockName = new Name(mockConfig, "192.168.1.100", 0x20, null);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertEquals(NbtAddress.SMBSERVER_NAME, nbtAddress.firstCalledName());
    }

    @Test
    void testFirstCalledName_SpecialHexCode() {
        // Test firstCalledName with special hex codes
        mockName = new Name(mockConfig, "DOMAIN", 0x1B, null); // Domain Master Browser
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertEquals(NbtAddress.SMBSERVER_NAME, nbtAddress.firstCalledName());

        mockName = new Name(mockConfig, "DOMAIN", 0x1C, null); // Domain Controller
        nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertEquals(NbtAddress.SMBSERVER_NAME, nbtAddress.firstCalledName());

        mockName = new Name(mockConfig, "DOMAIN", 0x1D, null); // Master Browser
        nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertEquals(NbtAddress.SMBSERVER_NAME, nbtAddress.firstCalledName());
    }

    @Test
    void testNextCalledName_InitialCall() {
        // Test nextCalledName when calledName is hostName.name initially
        mockName = new Name(mockConfig, "MYSERVER", 0x20, null);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        nbtAddress.firstCalledName(); // Initialize calledName
        assertEquals(NbtAddress.SMBSERVER_NAME, nbtAddress.nextCalledName(mockContext));
    }

    @Test
    void testNextCalledName_SmbServerName_NameType0x1D() throws UnknownHostException {
        // Test nextCalledName when calledName is SMBSERVER_NAME and nameType is 0x1D
        when(mockContext.getNameServiceClient()).thenReturn(mockNameServiceClient);
        mockName = new Name(mockConfig, "MASTERBROWSER", 0x1D, null);
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
        when(mockContext.getNameServiceClient()).thenReturn(mockNameServiceClient);
        mockName = new Name(mockConfig, "HOST", 0x20, null);
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
        when(mockContext.getNameServiceClient()).thenReturn(mockNameServiceClient);
        mockName = new Name(mockConfig, "HOST", 0x20, null);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        nbtAddress.calledName = NbtAddress.SMBSERVER_NAME; // Manually set for this test case

        when(mockNameServiceClient.getNodeStatus(nbtAddress)).thenThrow(new UnknownHostException());

        assertNull(nbtAddress.nextCalledName(mockContext));
        verify(mockNameServiceClient).getNodeStatus(nbtAddress);
    }

    @Test
    void testNextCalledName_OtherCases() {
        // Test nextCalledName for other cases where calledName is not hostName.name or SMBSERVER_NAME
        mockName = new Name(mockConfig, "HOST", 0x20, null);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        nbtAddress.calledName = "SOME_OTHER_NAME"; // Manually set for this test case
        assertNull(nbtAddress.nextCalledName(mockContext));
    }

    @Test
    void testGetHostName_KnownHost() {
        // Test getHostName when hostname is known
        mockName = new Name(mockConfig, "KNOWNHOST", 0x20, null);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertEquals("KNOWNHOST", nbtAddress.getHostName());
    }

    @Test
    void testGetHostName_UnknownHost() {
        // Test getHostName when hostname is unknown, should return IP address
        mockName = new Name(mockConfig, "0.0.0.0", 0, null);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertEquals("192.168.1.1", nbtAddress.getHostAddress());
        assertEquals("192.168.1.1", nbtAddress.getHostName());
    }

    @Test
    void testGetName() {
        // Test getName method
        mockName = new Name(mockConfig, "TEST", 0x20, null);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertSame(mockName, nbtAddress.getName());
    }

    @Test
    void testGetAddress() {
        // Test getAddress for correct byte array conversion
        mockName = new Name(mockConfig, "TEST", 0x20, null);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertArrayEquals(new byte[] { (byte) 192, (byte) 168, (byte) 1, (byte) 1 }, nbtAddress.getAddress());
    }

    @Test
    void testGetInetAddress() throws UnknownHostException {
        // Test getInetAddress for correct InetAddress creation
        mockName = new Name(mockConfig, "TESTHOST", 0x20, null);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        InetAddress expectedInetAddress = InetAddress.getByName("192.168.1.1");
        assertEquals(expectedInetAddress, nbtAddress.getInetAddress());
    }

    @Test
    void testToInetAddress() throws UnknownHostException {
        // Test toInetAddress (delegates to getInetAddress)
        mockName = new Name(mockConfig, "TESTHOST", 0x20, null);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        InetAddress expectedInetAddress = InetAddress.getByName("192.168.1.1");
        assertEquals(expectedInetAddress, nbtAddress.toInetAddress());
    }

    @Test
    void testGetHostAddress() {
        // Test getHostAddress for correct string format
        mockName = new Name(mockConfig, "TEST", 0x20, null);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertEquals("192.168.1.1", nbtAddress.getHostAddress());
    }

    @Test
    void testGetNameType() {
        // Test getNameType
        mockName = new Name(mockConfig, "TEST", 0x20, null);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertEquals(0x20, nbtAddress.getNameType());
    }

    @Test
    void testHashCode() {
        // Test hashCode consistency
        mockName = new Name(mockConfig, "TEST1", 0x20, null);
        Name mockName2 = new Name(mockConfig, "TEST2", 0x20, null);
        NbtAddress nbtAddress1 = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        NbtAddress nbtAddress2 = new NbtAddress(mockName2, testAddressInt, true, NbtAddress.B_NODE); // Different name, group, nodeType
        assertEquals(nbtAddress1.hashCode(), nbtAddress2.hashCode());
        assertEquals(testAddressInt, nbtAddress1.hashCode());
    }

    @Test
    void testEquals() {
        // Test equals method
        mockName = new Name(mockConfig, "TEST1", 0x20, null);
        Name mockName2 = new Name(mockConfig, "TEST2", 0x20, null);
        Name mockName3 = new Name(mockConfig, "TEST3", 0x20, null);
        NbtAddress nbtAddress1 = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        NbtAddress nbtAddress2 = new NbtAddress(mockName2, testAddressInt, true, NbtAddress.B_NODE); // Same address, different other fields
        NbtAddress nbtAddress3 = new NbtAddress(mockName3, 0xC0A80102, false, NbtAddress.H_NODE); // Different address

        assertTrue(nbtAddress1.equals(nbtAddress2)); // Should be true as only address is compared
        assertFalse(nbtAddress1.equals(nbtAddress3));
        assertFalse(nbtAddress1.equals(null));
        assertFalse(nbtAddress1.equals("some string"));
    }

    @Test
    void testToString() {
        // Test toString method
        mockName = new Name(mockConfig, "TESTHOST", 0x00, null);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertEquals("TESTHOST<00>/192.168.1.1", nbtAddress.toString());
    }

    // Tests for methods that call checkData(CIFSContext tc)
    @Test
    void testIsGroupAddress_CheckDataCalled() throws UnknownHostException {
        // Test isGroupAddress when checkData is called (hostName is unknown)
        when(mockContext.getNameServiceClient()).thenReturn(mockNameServiceClient);
        mockName = new Name(mockConfig, "0.0.0.0", 0, null);
        when(mockNameServiceClient.getNbtAllByAddress(any(NetbiosAddress.class))).thenReturn(new NbtAddress[0]);

        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, true, NbtAddress.H_NODE);
        assertTrue(nbtAddress.isGroupAddress(mockContext));
        verify(mockNameServiceClient).getNbtAllByAddress(any(NetbiosAddress.class));
    }

    @Test
    void testIsGroupAddress_NoCheckDataCall() throws UnknownHostException {
        // Test isGroupAddress when checkData is NOT called (hostName is known)
        mockName = new Name(mockConfig, "KNOWNHOST", 0x20, null);

        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        assertFalse(nbtAddress.isGroupAddress(mockContext));
        // No need to verify since we're not setting up the mock context
    }

    @Test
    void testGetNodeType_CheckDataCalled() throws UnknownHostException {
        // Test getNodeType when checkData is called (hostName is unknown)
        when(mockContext.getNameServiceClient()).thenReturn(mockNameServiceClient);
        mockName = new Name(mockConfig, "0.0.0.0", 0, null);
        when(mockNameServiceClient.getNbtAllByAddress(any(NetbiosAddress.class))).thenReturn(new NbtAddress[0]);

        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.P_NODE);
        assertEquals(NbtAddress.P_NODE, nbtAddress.getNodeType(mockContext));
        verify(mockNameServiceClient).getNbtAllByAddress(any(NetbiosAddress.class));
    }

    // Tests for methods that call checkNodeStatusData(CIFSContext tc)
    @Test
    void testIsBeingDeleted_CheckNodeStatusDataCalled() throws UnknownHostException {
        // Test isBeingDeleted when checkNodeStatusData is called (isDataFromNodeStatus is false)
        when(mockContext.getNameServiceClient()).thenReturn(mockNameServiceClient);
        mockName = new Name(mockConfig, "HOST", 0x20, null);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE); // isDataFromNodeStatus is false by default constructor
        when(mockNameServiceClient.getNbtAllByAddress(any(NetbiosAddress.class))).thenReturn(new NbtAddress[0]);

        assertFalse(nbtAddress.isBeingDeleted(mockContext)); // Default value before update
        verify(mockNameServiceClient).getNbtAllByAddress(any(NetbiosAddress.class));
    }

    @Test
    void testIsBeingDeleted_NoCheckNodeStatusDataCall() throws UnknownHostException {
        // Test isBeingDeleted when checkNodeStatusData is NOT called (isDataFromNodeStatus is true)
        mockName = new Name(mockConfig, "HOST", 0x20, null);
        NbtAddress nbtAddress =
                new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE, true, false, false, false, testMacAddress); // isDataFromNodeStatus is true by constructor

        assertTrue(nbtAddress.isBeingDeleted(mockContext));
        // No need to verify since we're not setting up the mock context
    }

    @Test
    void testIsInConflict_CheckNodeStatusDataCalled() throws UnknownHostException {
        // Test isInConflict when checkNodeStatusData is called
        when(mockContext.getNameServiceClient()).thenReturn(mockNameServiceClient);
        mockName = new Name(mockConfig, "HOST", 0x20, null);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        when(mockNameServiceClient.getNbtAllByAddress(any(NetbiosAddress.class))).thenReturn(new NbtAddress[0]);

        assertFalse(nbtAddress.isInConflict(mockContext));
        verify(mockNameServiceClient).getNbtAllByAddress(any(NetbiosAddress.class));
    }

    @Test
    void testIsActive_CheckNodeStatusDataCalled() throws UnknownHostException {
        // Test isActive when checkNodeStatusData is called
        when(mockContext.getNameServiceClient()).thenReturn(mockNameServiceClient);
        mockName = new Name(mockConfig, "HOST", 0x20, null);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        when(mockNameServiceClient.getNbtAllByAddress(any(NetbiosAddress.class))).thenReturn(new NbtAddress[0]);

        assertFalse(nbtAddress.isActive(mockContext));
        verify(mockNameServiceClient).getNbtAllByAddress(any(NetbiosAddress.class));
    }

    @Test
    void testIsPermanent_CheckNodeStatusDataCalled() throws UnknownHostException {
        // Test isPermanent when checkNodeStatusData is called
        when(mockContext.getNameServiceClient()).thenReturn(mockNameServiceClient);
        mockName = new Name(mockConfig, "HOST", 0x20, null);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        when(mockNameServiceClient.getNbtAllByAddress(any(NetbiosAddress.class))).thenReturn(new NbtAddress[0]);

        assertFalse(nbtAddress.isPermanent(mockContext));
        verify(mockNameServiceClient).getNbtAllByAddress(any(NetbiosAddress.class));
    }

    @Test
    void testGetMacAddress_CheckNodeStatusDataCalled() throws UnknownHostException {
        // Test getMacAddress when checkNodeStatusData is called
        when(mockContext.getNameServiceClient()).thenReturn(mockNameServiceClient);
        mockName = new Name(mockConfig, "HOST", 0x20, null);
        NbtAddress nbtAddress = new NbtAddress(mockName, testAddressInt, false, NbtAddress.H_NODE);
        when(mockNameServiceClient.getNbtAllByAddress(any(NetbiosAddress.class))).thenReturn(new NbtAddress[0]);

        assertNull(nbtAddress.getMacAddress(mockContext)); // Default value before update
        verify(mockNameServiceClient).getNbtAllByAddress(any(NetbiosAddress.class));
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