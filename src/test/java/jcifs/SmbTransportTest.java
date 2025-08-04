package jcifs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class SmbTransportTest {

    @Mock
    private SmbTransport smbTransport;

    @Mock
    private CIFSContext cifsContext;

    @Mock
    private Address remoteAddress;

    @BeforeEach
    void setUp() {
        // Common setup for mocks if needed
    }

    @Test
    void testGetContext() {
        // Arrange
        when(smbTransport.getContext()).thenReturn(cifsContext);

        // Act
        CIFSContext result = smbTransport.getContext();

        // Assert
        assertNotNull(result, "Context should not be null");
        assertEquals(cifsContext, result, "Returned context should be the mocked context");
        verify(smbTransport).getContext(); // Verify that the method was called
    }

    @Test
    void testUnwrap() {
        // Arrange
        SmbTransport mockUnwrappedTransport = smbTransport; // Mocking unwrap to return itself for simplicity
        when(smbTransport.unwrap(SmbTransport.class)).thenReturn(mockUnwrappedTransport);

        // Act
        SmbTransport result = smbTransport.unwrap(SmbTransport.class);

        // Assert
        assertNotNull(result, "Unwrapped transport should not be null");
        assertEquals(mockUnwrappedTransport, result, "Returned unwrapped transport should be the mocked one");
        verify(smbTransport).unwrap(SmbTransport.class); // Verify that the method was called
    }

    @Test
    void testClose() throws Exception {
        // Act
        smbTransport.close();

        // Assert
        verify(smbTransport).close(); // Verify that the close method was called
    }

    @Test
    void testGetRemoteAddress() {
        // Arrange
        when(smbTransport.getRemoteAddress()).thenReturn(remoteAddress);

        // Act
        Address result = smbTransport.getRemoteAddress();

        // Assert
        assertNotNull(result, "Remote address should not be null");
        assertEquals(remoteAddress, result, "Returned remote address should be the mocked address");
        verify(smbTransport).getRemoteAddress(); // Verify that the method was called
    }

    @Test
    void testGetRemoteHostName() {
        // Arrange
        String hostName = "testHost";
        when(smbTransport.getRemoteHostName()).thenReturn(hostName);

        // Act
        String result = smbTransport.getRemoteHostName();

        // Assert
        assertNotNull(result, "Remote host name should not be null");
        assertEquals(hostName, result, "Returned remote host name should be the mocked host name");
        verify(smbTransport).getRemoteHostName(); // Verify that the method was called
    }
}
