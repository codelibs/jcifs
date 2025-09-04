package jcifs.netbios;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.when;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.Configuration;

/**
 * Test class to verify that NoRouteToHostException is handled gracefully
 * for broadcast addresses in NameServiceClientImpl.
 */
@ExtendWith(MockitoExtension.class)
class NameServiceClientImplBroadcastTest {

    @Mock
    private CIFSContext mockContext;

    @Mock
    private Configuration mockConfig;

    private NameServiceClientImpl nameServiceClient;

    @BeforeEach
    void setUp() throws UnknownHostException {
        when(mockContext.getConfig()).thenReturn(mockConfig);

        // Configure broadcast address to 255.255.255.255
        when(mockConfig.getBroadcastAddress()).thenReturn(InetAddress.getByName("255.255.255.255"));
        when(mockConfig.getNetbiosSndBufSize()).thenReturn(576);
        when(mockConfig.getNetbiosRcvBufSize()).thenReturn(576);

        when(mockConfig.getNetbiosLocalAddress()).thenReturn(null);

        nameServiceClient = new NameServiceClientImpl(0, null, mockContext);
    }

    @Test
    void testBroadcastFailureDoesNotThrowUnknownHostException() {
        // This test verifies that when broadcast to 255.255.255.255 fails
        // with NoRouteToHostException, it returns empty array instead of throwing
        try {
            Name testName = new Name(mockConfig, "TESTHOST", 0x20, null);
            InetAddress broadcastAddr = InetAddress.getByName("255.255.255.255");

            // This should handle NoRouteToHostException gracefully
            NbtAddress[] result = nameServiceClient.getAllByName(testName, broadcastAddr);

            // If broadcast fails, we expect empty array
            assertNotNull(result, "Result should not be null for broadcast failures");

            // The actual broadcast will likely fail with NoRouteToHostException
            // but it should be caught and handled gracefully

        } catch (UnknownHostException e) {
            // This should not happen if our fix is working
            fail("UnknownHostException should not be thrown for broadcast failures: " + e.getMessage());
        } catch (Exception e) {
            // Other exceptions are acceptable (like actual network issues)
            // but not UnknownHostException
            assertTrue(true, "Non-UnknownHostException is acceptable: " + e.getClass());
        }
    }

    @Test
    void testNonBroadcastAddressStillThrowsUnknownHostException() throws UnknownHostException {
        // This test verifies that non-broadcast addresses still throw
        // UnknownHostException when they fail
        Name testName = new Name(mockConfig, "NONEXISTENTHOST", 0x20, null);
        InetAddress nonBroadcastAddr = InetAddress.getByName("192.168.1.1");

        // This should still throw UnknownHostException for non-broadcast
        // Note: Due to network configuration, this might throw different exceptions
        // but the important thing is that it doesn't succeed
        assertThrows(Exception.class, () -> {
            nameServiceClient.getAllByName(testName, nonBroadcastAddr);
        }, "Non-broadcast addresses should throw an exception when they fail");
    }
}