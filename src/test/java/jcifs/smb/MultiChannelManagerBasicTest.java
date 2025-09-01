package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.net.InetAddress;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.config.BaseConfiguration;

/**
 * Basic tests for MultiChannelManager to verify the createChannelTransport implementation.
 */
public class MultiChannelManagerBasicTest {

    private MultiChannelManager multiChannelManager;
    private Configuration config;

    @BeforeEach
    void setUp() throws Exception {
        // Create a basic configuration for testing
        this.config = new BaseConfiguration(true);
        this.multiChannelManager = new MultiChannelManager(config);
    }

    @Test
    @DisplayName("MultiChannelManager should initialize successfully")
    void testInitialization() {
        assertNotNull(multiChannelManager);
        MultiChannelManager.ChannelStatistics stats = multiChannelManager.getStatistics();
        assertEquals(0, stats.getActiveSessions());
        assertEquals(0, stats.getTotalChannels());
    }

    @Test
    @DisplayName("createChannelTransport should fail with null addresses")
    void testCreateChannelTransportWithNullAddresses() {
        // Use reflection to access private method for testing
        Exception exception = assertThrows(Exception.class, () -> {
            java.lang.reflect.Method method =
                    MultiChannelManager.class.getDeclaredMethod("createChannelTransport", InetAddress.class, InetAddress.class);
            method.setAccessible(true);
            method.invoke(multiChannelManager, null, null);
        });

        // Check that the root cause is CIFSException
        assertTrue(exception instanceof java.lang.reflect.InvocationTargetException);
        Throwable cause = ((java.lang.reflect.InvocationTargetException) exception).getCause();
        assertTrue(cause instanceof CIFSException);
        assertTrue(cause.getMessage().contains("Failed to create multi-channel transport"));
    }

    @Test
    @DisplayName("createChannelTransport should handle localhost addresses")
    void testCreateChannelTransportWithLocalhostAddresses() throws Exception {
        InetAddress localhost = InetAddress.getLocalHost();
        InetAddress loopback = InetAddress.getLoopbackAddress();

        // Use reflection to access private method for testing
        java.lang.reflect.Method method =
                MultiChannelManager.class.getDeclaredMethod("createChannelTransport", InetAddress.class, InetAddress.class);
        method.setAccessible(true);

        // This should fail because localhost doesn't support SMB multi-channel
        // but the method should not throw NullPointerException
        try {
            method.invoke(multiChannelManager, localhost, loopback);
            // If it doesn't throw, that's unexpected for localhost
            fail("Expected CIFSException for localhost multi-channel attempt");
        } catch (java.lang.reflect.InvocationTargetException e) {
            // We expect this to fail, but it should be a CIFSException, not a NullPointerException
            assertTrue(e.getCause() instanceof CIFSException);
            assertTrue(e.getCause().getMessage().contains("Failed to create multi-channel transport"));
        }
    }

    @Test
    @DisplayName("MultiChannelManager should shutdown cleanly")
    void testShutdown() {
        assertDoesNotThrow(() -> {
            multiChannelManager.shutdown();
        });
    }

    @Test
    @DisplayName("createDefaultContext should work")
    void testCreateDefaultContext() throws Exception {
        // Use reflection to access private method for testing
        java.lang.reflect.Method method = MultiChannelManager.class.getDeclaredMethod("createDefaultContext");
        method.setAccessible(true);

        Object context = method.invoke(multiChannelManager);
        assertNotNull(context);
        assertTrue(context instanceof jcifs.CIFSContext);
    }
}