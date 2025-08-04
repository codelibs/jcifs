package jcifs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class NameServiceClientTest {

    @Mock
    private NameServiceClient nameServiceClient;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testGetLocalHost() {
        // Arrange
        NetbiosAddress expectedAddress = mock(NetbiosAddress.class);
        when(nameServiceClient.getLocalHost()).thenReturn(expectedAddress);

        // Act
        NetbiosAddress actualAddress = nameServiceClient.getLocalHost();

        // Assert
        assertNotNull(actualAddress);
        assertEquals(expectedAddress, actualAddress);
        verify(nameServiceClient, times(1)).getLocalHost();
    }

    @Test
    void testGetLocalName() {
        // Arrange
        NetbiosName expectedName = mock(NetbiosName.class);
        when(nameServiceClient.getLocalName()).thenReturn(expectedName);

        // Act
        NetbiosName actualName = nameServiceClient.getLocalName();

        // Assert
        assertNotNull(actualName);
        assertEquals(expectedName, actualName);
        verify(nameServiceClient, times(1)).getLocalName();
    }

    @Test
    void testGetUnknownName() {
        // Arrange
        NetbiosName expectedName = mock(NetbiosName.class);
        when(nameServiceClient.getUnknownName()).thenReturn(expectedName);

        // Act
        NetbiosName actualName = nameServiceClient.getUnknownName();

        // Assert
        assertNotNull(actualName);
        assertEquals(expectedName, actualName);
        verify(nameServiceClient, times(1)).getUnknownName();
    }

    @Test
    void testGetNbtAllByAddress_NetbiosAddress() throws UnknownHostException {
        // Arrange
        NetbiosAddress inputAddress = mock(NetbiosAddress.class);
        NetbiosAddress[] expectedAddresses = { mock(NetbiosAddress.class), mock(NetbiosAddress.class) };
        when(nameServiceClient.getNbtAllByAddress(inputAddress)).thenReturn(expectedAddresses);

        // Act
        NetbiosAddress[] actualAddresses = nameServiceClient.getNbtAllByAddress(inputAddress);

        // Assert
        assertNotNull(actualAddresses);
        assertEquals(2, actualAddresses.length);
        assertEquals(expectedAddresses[0], actualAddresses[0]);
        assertEquals(expectedAddresses[1], actualAddresses[1]);
        verify(nameServiceClient, times(1)).getNbtAllByAddress(inputAddress);
    }

    @Test
    void testGetNbtAllByAddress_NetbiosAddress_ThrowsUnknownHostException() throws UnknownHostException {
        // Arrange
        NetbiosAddress inputAddress = mock(NetbiosAddress.class);
        when(nameServiceClient.getNbtAllByAddress(inputAddress)).thenThrow(new UnknownHostException("Host not found"));

        // Act & Assert
        assertThrows(UnknownHostException.class, () -> nameServiceClient.getNbtAllByAddress(inputAddress));
        verify(nameServiceClient, times(1)).getNbtAllByAddress(inputAddress);
    }

    @Test
    void testGetNbtAllByAddress_StringIntString() throws UnknownHostException {
        // Arrange
        String host = "testHost";
        int type = 0x20;
        String scope = "testScope";
        NetbiosAddress[] expectedAddresses = { mock(NetbiosAddress.class) };
        when(nameServiceClient.getNbtAllByAddress(host, type, scope)).thenReturn(expectedAddresses);

        // Act
        NetbiosAddress[] actualAddresses = nameServiceClient.getNbtAllByAddress(host, type, scope);

        // Assert
        assertNotNull(actualAddresses);
        assertEquals(1, actualAddresses.length);
        assertEquals(expectedAddresses[0], actualAddresses[0]);
        verify(nameServiceClient, times(1)).getNbtAllByAddress(host, type, scope);
    }

    @Test
    void testGetNbtAllByAddress_StringIntString_ThrowsUnknownHostException() throws UnknownHostException {
        // Arrange
        String host = "testHost";
        int type = 0x20;
        String scope = "testScope";
        when(nameServiceClient.getNbtAllByAddress(host, type, scope)).thenThrow(new UnknownHostException("Host not found"));

        // Act & Assert
        assertThrows(UnknownHostException.class, () -> nameServiceClient.getNbtAllByAddress(host, type, scope));
        verify(nameServiceClient, times(1)).getNbtAllByAddress(host, type, scope);
    }

    @Test
    void testGetNbtAllByAddress_String() throws UnknownHostException {
        // Arrange
        String host = "testHost";
        NetbiosAddress[] expectedAddresses = { mock(NetbiosAddress.class) };
        when(nameServiceClient.getNbtAllByAddress(host)).thenReturn(expectedAddresses);

        // Act
        NetbiosAddress[] actualAddresses = nameServiceClient.getNbtAllByAddress(host);

        // Assert
        assertNotNull(actualAddresses);
        assertEquals(1, actualAddresses.length);
        assertEquals(expectedAddresses[0], actualAddresses[0]);
        verify(nameServiceClient, times(1)).getNbtAllByAddress(host);
    }

    @Test
    void testGetNbtAllByAddress_String_ThrowsUnknownHostException() throws UnknownHostException {
        // Arrange
        String host = "testHost";
        when(nameServiceClient.getNbtAllByAddress(host)).thenThrow(new UnknownHostException("Host not found"));

        // Act & Assert
        assertThrows(UnknownHostException.class, () -> nameServiceClient.getNbtAllByAddress(host));
        verify(nameServiceClient, times(1)).getNbtAllByAddress(host);
    }

    @Test
    void testGetNbtAllByName() throws UnknownHostException {
        // Arrange
        String host = "testHost";
        int type = 0x20;
        String scope = "testScope";
        InetAddress svr = mock(InetAddress.class);
        NetbiosAddress[] expectedAddresses = { mock(NetbiosAddress.class) };
        when(nameServiceClient.getNbtAllByName(host, type, scope, svr)).thenReturn(expectedAddresses);

        // Act
        NetbiosAddress[] actualAddresses = nameServiceClient.getNbtAllByName(host, type, scope, svr);

        // Assert
        assertNotNull(actualAddresses);
        assertEquals(1, actualAddresses.length);
        assertEquals(expectedAddresses[0], actualAddresses[0]);
        verify(nameServiceClient, times(1)).getNbtAllByName(host, type, scope, svr);
    }

    @Test
    void testGetNbtAllByName_ThrowsUnknownHostException() throws UnknownHostException {
        // Arrange
        String host = "testHost";
        int type = 0x20;
        String scope = "testScope";
        InetAddress svr = mock(InetAddress.class);
        when(nameServiceClient.getNbtAllByName(host, type, scope, svr)).thenThrow(new UnknownHostException("Host not found"));

        // Act & Assert
        assertThrows(UnknownHostException.class, () -> nameServiceClient.getNbtAllByName(host, type, scope, svr));
        verify(nameServiceClient, times(1)).getNbtAllByName(host, type, scope, svr);
    }

    @Test
    void testGetNbtByName_StringIntStringInetAddress() throws UnknownHostException {
        // Arrange
        String host = "testHost";
        int type = 0x20;
        String scope = "testScope";
        InetAddress svr = mock(InetAddress.class);
        NetbiosAddress expectedAddress = mock(NetbiosAddress.class);
        when(nameServiceClient.getNbtByName(host, type, scope, svr)).thenReturn(expectedAddress);

        // Act
        NetbiosAddress actualAddress = nameServiceClient.getNbtByName(host, type, scope, svr);

        // Assert
        assertNotNull(actualAddress);
        assertEquals(expectedAddress, actualAddress);
        verify(nameServiceClient, times(1)).getNbtByName(host, type, scope, svr);
    }

    @Test
    void testGetNbtByName_StringIntStringInetAddress_ThrowsUnknownHostException() throws UnknownHostException {
        // Arrange
        String host = "testHost";
        int type = 0x20;
        String scope = "testScope";
        InetAddress svr = mock(InetAddress.class);
        when(nameServiceClient.getNbtByName(host, type, scope, svr)).thenThrow(new UnknownHostException("Host not found"));

        // Act & Assert
        assertThrows(UnknownHostException.class, () -> nameServiceClient.getNbtByName(host, type, scope, svr));
        verify(nameServiceClient, times(1)).getNbtByName(host, type, scope, svr);
    }

    @Test
    void testGetNbtByName_StringIntString() throws UnknownHostException {
        // Arrange
        String host = "testHost";
        int type = 0x20;
        String scope = "testScope";
        NetbiosAddress expectedAddress = mock(NetbiosAddress.class);
        when(nameServiceClient.getNbtByName(host, type, scope)).thenReturn(expectedAddress);

        // Act
        NetbiosAddress actualAddress = nameServiceClient.getNbtByName(host, type, scope);

        // Assert
        assertNotNull(actualAddress);
        assertEquals(expectedAddress, actualAddress);
        verify(nameServiceClient, times(1)).getNbtByName(host, type, scope);
    }

    @Test
    void testGetNbtByName_StringIntString_ThrowsUnknownHostException() throws UnknownHostException {
        // Arrange
        String host = "testHost";
        int type = 0x20;
        String scope = "testScope";
        when(nameServiceClient.getNbtByName(host, type, scope)).thenThrow(new UnknownHostException("Host not found"));

        // Act & Assert
        assertThrows(UnknownHostException.class, () -> nameServiceClient.getNbtByName(host, type, scope));
        verify(nameServiceClient, times(1)).getNbtByName(host, type, scope);
    }

    @Test
    void testGetNbtByName_String() throws UnknownHostException {
        // Arrange
        String host = "testHost";
        NetbiosAddress expectedAddress = mock(NetbiosAddress.class);
        when(nameServiceClient.getNbtByName(host)).thenReturn(expectedAddress);

        // Act
        NetbiosAddress actualAddress = nameServiceClient.getNbtByName(host);

        // Assert
        assertNotNull(actualAddress);
        assertEquals(expectedAddress, actualAddress);
        verify(nameServiceClient, times(1)).getNbtByName(host);
    }

    @Test
    void testGetNbtByName_String_ThrowsUnknownHostException() throws UnknownHostException {
        // Arrange
        String host = "testHost";
        when(nameServiceClient.getNbtByName(host)).thenThrow(new UnknownHostException("Host not found"));

        // Act & Assert
        assertThrows(UnknownHostException.class, () -> nameServiceClient.getNbtByName(host));
        verify(nameServiceClient, times(1)).getNbtByName(host);
    }

    @Test
    void testGetNodeStatus() throws UnknownHostException {
        // Arrange
        NetbiosAddress nbtAddress = mock(NetbiosAddress.class);
        NetbiosAddress[] expectedAddresses = { mock(NetbiosAddress.class) };
        when(nameServiceClient.getNodeStatus(nbtAddress)).thenReturn(expectedAddresses);

        // Act
        NetbiosAddress[] actualAddresses = nameServiceClient.getNodeStatus(nbtAddress);

        // Assert
        assertNotNull(actualAddresses);
        assertEquals(1, actualAddresses.length);
        assertEquals(expectedAddresses[0], actualAddresses[0]);
        verify(nameServiceClient, times(1)).getNodeStatus(nbtAddress);
    }

    @Test
    void testGetNodeStatus_ThrowsUnknownHostException() throws UnknownHostException {
        // Arrange
        NetbiosAddress nbtAddress = mock(NetbiosAddress.class);
        when(nameServiceClient.getNodeStatus(nbtAddress)).thenThrow(new UnknownHostException("Node status not found"));

        // Act & Assert
        assertThrows(UnknownHostException.class, () -> nameServiceClient.getNodeStatus(nbtAddress));
        verify(nameServiceClient, times(1)).getNodeStatus(nbtAddress);
    }

    @Test
    void testGetAllByName() throws UnknownHostException {
        // Arrange
        String hostname = "testHostname";
        boolean possibleNTDomainOrWorkgroup = true;
        Address[] expectedAddresses = { mock(Address.class) };
        when(nameServiceClient.getAllByName(hostname, possibleNTDomainOrWorkgroup)).thenReturn(expectedAddresses);

        // Act
        Address[] actualAddresses = nameServiceClient.getAllByName(hostname, possibleNTDomainOrWorkgroup);

        // Assert
        assertNotNull(actualAddresses);
        assertEquals(1, actualAddresses.length);
        assertEquals(expectedAddresses[0], actualAddresses[0]);
        verify(nameServiceClient, times(1)).getAllByName(hostname, possibleNTDomainOrWorkgroup);
    }

    @Test
    void testGetAllByName_ThrowsUnknownHostException() throws UnknownHostException {
        // Arrange
        String hostname = "testHostname";
        boolean possibleNTDomainOrWorkgroup = true;
        when(nameServiceClient.getAllByName(hostname, possibleNTDomainOrWorkgroup)).thenThrow(new UnknownHostException("Host not found"));

        // Act & Assert
        assertThrows(UnknownHostException.class, () -> nameServiceClient.getAllByName(hostname, possibleNTDomainOrWorkgroup));
        verify(nameServiceClient, times(1)).getAllByName(hostname, possibleNTDomainOrWorkgroup);
    }

    @Test
    void testGetByName_StringBoolean() throws UnknownHostException {
        // Arrange
        String hostname = "testHostname";
        boolean possibleNTDomainOrWorkgroup = true;
        Address expectedAddress = mock(Address.class);
        when(nameServiceClient.getByName(hostname, possibleNTDomainOrWorkgroup)).thenReturn(expectedAddress);

        // Act
        Address actualAddress = nameServiceClient.getByName(hostname, possibleNTDomainOrWorkgroup);

        // Assert
        assertNotNull(actualAddress);
        assertEquals(expectedAddress, actualAddress);
        verify(nameServiceClient, times(1)).getByName(hostname, possibleNTDomainOrWorkgroup);
    }

    @Test
    void testGetByName_StringBoolean_ThrowsUnknownHostException() throws UnknownHostException {
        // Arrange
        String hostname = "testHostname";
        boolean possibleNTDomainOrWorkgroup = true;
        when(nameServiceClient.getByName(hostname, possibleNTDomainOrWorkgroup)).thenThrow(new UnknownHostException("Host not found"));

        // Act & Assert
        assertThrows(UnknownHostException.class, () -> nameServiceClient.getByName(hostname, possibleNTDomainOrWorkgroup));
        verify(nameServiceClient, times(1)).getByName(hostname, possibleNTDomainOrWorkgroup);
    }

    @Test
    void testGetByName_String() throws UnknownHostException {
        // Arrange
        String hostname = "testHostname";
        Address expectedAddress = mock(Address.class);
        when(nameServiceClient.getByName(hostname)).thenReturn(expectedAddress);

        // Act
        Address actualAddress = nameServiceClient.getByName(hostname);

        // Assert
        assertNotNull(actualAddress);
        assertEquals(expectedAddress, actualAddress);
        verify(nameServiceClient, times(1)).getByName(hostname);
    }

    @Test
    void testGetByName_String_ThrowsUnknownHostException() throws UnknownHostException {
        // Arrange
        String hostname = "testHostname";
        when(nameServiceClient.getByName(hostname)).thenThrow(new UnknownHostException("Host not found"));

        // Act & Assert
        assertThrows(UnknownHostException.class, () -> nameServiceClient.getByName(hostname));
        verify(nameServiceClient, times(1)).getByName(hostname);
    }
}