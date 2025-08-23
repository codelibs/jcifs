/*
 * © 2025 CodeLibs, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package jcifs.internal.smb2.rdma;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Properties;

import org.junit.jupiter.api.Test;

import jcifs.CIFSException;
import jcifs.config.PropertyConfiguration;

/**
 * Test RDMA configuration properties
 */
public class RdmaConfigurationTest {

    @Test
    public void testDefaultRdmaConfiguration() throws CIFSException {
        Properties props = new Properties();
        PropertyConfiguration config = new PropertyConfiguration(props);

        // Test default values
        assertFalse(config.isUseRDMA(), "RDMA should be disabled by default");
        assertEquals("auto", config.getRdmaProvider(), "Default provider should be auto");
        assertEquals(8192, config.getRdmaReadWriteThreshold(), "Default threshold should be 8KB");
        assertEquals(65536, config.getRdmaMaxSendSize(), "Default max send size should be 64KB");
        assertEquals(65536, config.getRdmaMaxReceiveSize(), "Default max receive size should be 64KB");
        assertEquals(255, config.getRdmaCredits(), "Default credits should be 255");
    }

    @Test
    public void testRdmaConfigurationProperties() throws CIFSException {
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.useRDMA", "true");
        props.setProperty("jcifs.smb.client.rdmaProvider", "disni");
        props.setProperty("jcifs.smb.client.rdmaReadWriteThreshold", "16384");
        props.setProperty("jcifs.smb.client.rdmaMaxSendSize", "131072");
        props.setProperty("jcifs.smb.client.rdmaMaxReceiveSize", "131072");
        props.setProperty("jcifs.smb.client.rdmaCredits", "512");

        PropertyConfiguration config = new PropertyConfiguration(props);

        assertTrue(config.isUseRDMA(), "RDMA should be enabled");
        assertEquals("disni", config.getRdmaProvider(), "Provider should be disni");
        assertEquals(16384, config.getRdmaReadWriteThreshold(), "Threshold should be 16KB");
        assertEquals(131072, config.getRdmaMaxSendSize(), "Max send size should be 128KB");
        assertEquals(131072, config.getRdmaMaxReceiveSize(), "Max receive size should be 128KB");
        assertEquals(512, config.getRdmaCredits(), "Credits should be 512");
    }

    @Test
    public void testRdmaConfigurationInvalidValues() throws CIFSException {
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.useRDMA", "invalid");
        props.setProperty("jcifs.smb.client.rdmaReadWriteThreshold", "invalid");
        props.setProperty("jcifs.smb.client.rdmaMaxSendSize", "invalid");
        props.setProperty("jcifs.smb.client.rdmaMaxReceiveSize", "invalid");
        props.setProperty("jcifs.smb.client.rdmaCredits", "invalid");

        PropertyConfiguration config = new PropertyConfiguration(props);

        // Invalid values should result in defaults
        assertFalse(config.isUseRDMA(), "Invalid boolean should default to false");
        assertEquals(8192, config.getRdmaReadWriteThreshold(), "Invalid number should use default");
        assertEquals(65536, config.getRdmaMaxSendSize(), "Invalid number should use default");
        assertEquals(65536, config.getRdmaMaxReceiveSize(), "Invalid number should use default");
        assertEquals(255, config.getRdmaCredits(), "Invalid number should use default");
    }

    @Test
    public void testRdmaProviderFallback() throws CIFSException {
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.useRDMA", "true");
        props.setProperty("jcifs.smb.client.rdmaProvider", "tcp");

        PropertyConfiguration config = new PropertyConfiguration(props);

        assertTrue(config.isUseRDMA(), "RDMA should be enabled");
        assertEquals("tcp", config.getRdmaProvider(), "Provider should be tcp");
    }

    @Test
    public void testRdmaAutoProvider() throws CIFSException {
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.useRDMA", "true");
        // Don't set provider, should default to auto

        PropertyConfiguration config = new PropertyConfiguration(props);

        assertTrue(config.isUseRDMA(), "RDMA should be enabled");
        assertEquals("auto", config.getRdmaProvider(), "Provider should default to auto");
    }
}
