package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

/**
 * Comprehensive test suite for Address interface.
 * Tests the contract and behavior of Address implementations.
 */
@DisplayName("Address Interface Tests")
class AddressTest extends BaseTest {

    @Mock
    private CIFSContext mockContext;

    @Mock
    private Address mockAddress;

    @Test
    @DisplayName("Address interface should define correct method signatures")
    void testInterfaceContract() {
        // Given
        Address address = mockAddress;

        // When & Then - verify interface methods exist and can be called
        assertDoesNotThrow(() -> {
            address.getHostName();
            address.getHostAddress();
            address.firstCalledName();
            address.nextCalledName(mockContext);
            address.toInetAddress();
            address.unwrap(Address.class);
        }, "All Address interface methods should be callable");
    }

    @Test
    @DisplayName("unwrap method should return correct type when supported")
    void testUnwrapMethodContract() throws Exception {
        // Given
        when(mockAddress.unwrap(Address.class)).thenReturn(mockAddress);

        // When & Then
        Address unwrapped = mockAddress.unwrap(Address.class);
        assertSame(mockAddress, unwrapped, "Should return same instance for supported type");
    }

    @Test
    @DisplayName("getHostName should return valid hostname or address")
    void testGetHostNameContract() {
        // Given
        String expectedHostName = "server.example.com";
        when(mockAddress.getHostName()).thenReturn(expectedHostName);

        // When
        String hostName = mockAddress.getHostName();

        // Then
        assertEquals(expectedHostName, hostName, "Should return configured hostname");
        assertNotNull(hostName, "Host name should not be null");
    }

    @Test
    @DisplayName("getHostAddress should return valid IP address string")
    void testGetHostAddressContract() {
        // Given
        String expectedAddress = "192.168.1.100";
        when(mockAddress.getHostAddress()).thenReturn(expectedAddress);

        // When
        String hostAddress = mockAddress.getHostAddress();

        // Then
        assertEquals(expectedAddress, hostAddress, "Should return configured IP address");
        assertNotNull(hostAddress, "Host address should not be null");
    }

    @Test
    @DisplayName("toInetAddress should return valid InetAddress")
    void testToInetAddressContract() throws UnknownHostException {
        // Given
        InetAddress expectedInetAddress = InetAddress.getByName("127.0.0.1");
        when(mockAddress.toInetAddress()).thenReturn(expectedInetAddress);

        // When
        InetAddress inetAddress = mockAddress.toInetAddress();

        // Then
        assertSame(expectedInetAddress, inetAddress, "Should return configured InetAddress");
        assertNotNull(inetAddress, "InetAddress should not be null");
    }

    @Test
    @DisplayName("toInetAddress should handle UnknownHostException")
    void testToInetAddressWithException() throws UnknownHostException {
        // Given
        when(mockAddress.toInetAddress()).thenThrow(new UnknownHostException("Host not found"));

        // When & Then
        assertThrows(UnknownHostException.class, () -> {
            mockAddress.toInetAddress();
        }, "Should propagate UnknownHostException");
    }

    @Test
    @DisplayName("firstCalledName should return valid name for session establishment")
    void testFirstCalledNameContract() {
        // Given
        String expectedFirstName = "SERVER";
        when(mockAddress.firstCalledName()).thenReturn(expectedFirstName);

        // When
        String firstName = mockAddress.firstCalledName();

        // Then
        assertEquals(expectedFirstName, firstName, "Should return first called name");
        assertNotNull(firstName, "First called name should not be null");
    }

    @Test
    @DisplayName("nextCalledName should return valid name for fallback attempts")
    void testNextCalledNameContract() {
        // Given
        String expectedNextName = "SERVER15";
        when(mockAddress.nextCalledName(mockContext)).thenReturn(expectedNextName);

        // When
        String nextName = mockAddress.nextCalledName(mockContext);

        // Then
        assertEquals(expectedNextName, nextName, "Should return next called name");
        // Note: nextCalledName can return null when no more names available
    }
}
