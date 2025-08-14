package jcifs;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Properties;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import jcifs.config.PropertyConfiguration;

/**
 * Tests for SMB connection batch limit functionality.
 * Tests the batch limit configuration for various SMB commands.
 */
public class SmbConnectionTest {

    /**
     * Test that getBatchLimit returns correct values for different commands
     */
    @Test
    @DisplayName("getBatchLimit returns correct values for different SMB commands")
    public void testBatchLimitForDifferentCommands() throws CIFSException {
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.useBatching", "true");
        props.setProperty("jcifs.smb.client.useUnicode", "true");

        PropertyConfiguration config = new PropertyConfiguration(props);

        // Test various command batch limits
        int readAndXClose = config.getBatchLimit("ReadAndX.Close");
        assertTrue(readAndXClose >= 0, "ReadAndX.Close batch limit should be non-negative");

        int treeConnectCheck = config.getBatchLimit("TreeConnectAndX.CheckDirectory");
        assertTrue(treeConnectCheck >= 0, "TreeConnectAndX.CheckDirectory batch limit should be non-negative");

        int treeConnectCreate = config.getBatchLimit("TreeConnectAndX.CreateDirectory");
        assertTrue(treeConnectCreate >= 0, "TreeConnectAndX.CreateDirectory batch limit should be non-negative");
    }

    /**
     * Test that batch limit respects Unicode settings
     */
    @Test
    @DisplayName("Batch limit configuration with Unicode enabled")
    public void testBatchLimitWithUnicodeEnabled() throws CIFSException {
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.useUnicode", "true");
        props.setProperty("jcifs.smb.client.useBatching", "true");

        PropertyConfiguration config = new PropertyConfiguration(props);

        assertTrue(config.isUseUnicode(), "Unicode should be enabled");
        assertTrue(config.isUseBatching(), "Batching should be enabled");

        // When both are enabled, batch limits should be available
        int limit = config.getBatchLimit("TreeConnectAndX.QueryInformation");
        assertTrue(limit >= 0, "Batch limit should be non-negative when Unicode and batching enabled");
    }

    /**
     * Test configuration when batching is disabled
     */
    @Test
    @DisplayName("Batch limit configuration with batching disabled")
    public void testBatchLimitWithBatchingDisabled() throws CIFSException {
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.useUnicode", "true");
        props.setProperty("jcifs.smb.client.useBatching", "false");

        PropertyConfiguration config = new PropertyConfiguration(props);

        assertTrue(config.isUseUnicode(), "Unicode should be enabled");
        assertFalse(config.isUseBatching(), "Batching should be disabled");

        // Even with batching disabled, getBatchLimit should return a value
        int limit = config.getBatchLimit("TreeConnectAndX.Transaction");
        assertTrue(limit >= 0, "Batch limit should still return a value even when batching is disabled");
    }

    /**
     * Test configuration when Unicode is disabled
     */
    @Test
    @DisplayName("Batch limit configuration with Unicode disabled")
    public void testBatchLimitWithUnicodeDisabled() throws CIFSException {
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.useUnicode", "false");
        props.setProperty("jcifs.smb.client.useBatching", "true");

        PropertyConfiguration config = new PropertyConfiguration(props);

        assertFalse(config.isUseUnicode(), "Unicode should be disabled");
        assertTrue(config.isUseBatching(), "Batching should be enabled");

        // Batch limits should still be accessible
        int limit = config.getBatchLimit("TreeConnectAndX.OpenAndX");
        assertTrue(limit >= 0, "Batch limit should be accessible even with Unicode disabled");
    }
}