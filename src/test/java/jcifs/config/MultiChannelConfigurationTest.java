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
package jcifs.config;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Properties;

import org.junit.jupiter.api.Test;

import jcifs.CIFSException;

/**
 * Unit tests for Multi-Channel configuration properties
 */
class MultiChannelConfigurationTest {

    @Test
    void testDefaultMultiChannelSettings() throws CIFSException {
        PropertyConfiguration config = new PropertyConfiguration(new Properties());

        assertTrue(config.isUseMultiChannel(), "Multi-channel should be enabled by default");
        assertEquals(4, config.getMaxChannels(), "Default max channels should be 4");
        assertEquals(1, config.getChannelBindingPolicy(), "Default binding policy should be preferred");
        assertEquals("adaptive", config.getLoadBalancingStrategy(), "Default strategy should be adaptive");
        assertEquals(10, config.getChannelHealthCheckInterval(), "Default health check interval should be 10");
    }

    @Test
    void testMultiChannelEnabledProperty() throws CIFSException {
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.useMultiChannel", "false");

        PropertyConfiguration config = new PropertyConfiguration(props);
        assertFalse(config.isUseMultiChannel());

        props.setProperty("jcifs.smb.client.useMultiChannel", "true");
        config = new PropertyConfiguration(props);
        assertTrue(config.isUseMultiChannel());
    }

    @Test
    void testMaxChannelsProperty() throws CIFSException {
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.maxChannels", "8");

        PropertyConfiguration config = new PropertyConfiguration(props);
        assertEquals(8, config.getMaxChannels());

        props.setProperty("jcifs.smb.client.maxChannels", "1");
        config = new PropertyConfiguration(props);
        assertEquals(1, config.getMaxChannels());
    }

    @Test
    void testChannelBindingPolicyProperty() throws CIFSException {
        Properties props = new Properties();

        // Test disabled
        props.setProperty("jcifs.smb.client.channelBindingPolicy", "disabled");
        PropertyConfiguration config = new PropertyConfiguration(props);
        assertEquals(0, config.getChannelBindingPolicy());

        // Test preferred (default)
        props.setProperty("jcifs.smb.client.channelBindingPolicy", "preferred");
        config = new PropertyConfiguration(props);
        assertEquals(1, config.getChannelBindingPolicy());

        // Test required
        props.setProperty("jcifs.smb.client.channelBindingPolicy", "required");
        config = new PropertyConfiguration(props);
        assertEquals(2, config.getChannelBindingPolicy());

        // Test invalid value defaults to preferred
        props.setProperty("jcifs.smb.client.channelBindingPolicy", "invalid");
        config = new PropertyConfiguration(props);
        assertEquals(1, config.getChannelBindingPolicy());
    }

    @Test
    void testLoadBalancingStrategyProperty() throws CIFSException {
        Properties props = new Properties();

        String[] strategies = { "round_robin", "least_loaded", "weighted_random", "affinity_based", "adaptive" };

        for (String strategy : strategies) {
            props.setProperty("jcifs.smb.client.loadBalancingStrategy", strategy);
            PropertyConfiguration config = new PropertyConfiguration(props);
            assertEquals(strategy, config.getLoadBalancingStrategy());
        }

        // Test case insensitivity
        props.setProperty("jcifs.smb.client.loadBalancingStrategy", "ADAPTIVE");
        PropertyConfiguration config = new PropertyConfiguration(props);
        assertEquals("ADAPTIVE", config.getLoadBalancingStrategy());
    }

    @Test
    void testChannelHealthCheckIntervalProperty() throws CIFSException {
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.channelHealthCheckInterval", "30");

        PropertyConfiguration config = new PropertyConfiguration(props);
        assertEquals(30, config.getChannelHealthCheckInterval());

        props.setProperty("jcifs.smb.client.channelHealthCheckInterval", "5");
        config = new PropertyConfiguration(props);
        assertEquals(5, config.getChannelHealthCheckInterval());
    }

    @Test
    void testCompleteMultiChannelConfiguration() throws CIFSException {
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.useMultiChannel", "true");
        props.setProperty("jcifs.smb.client.maxChannels", "6");
        props.setProperty("jcifs.smb.client.channelBindingPolicy", "required");
        props.setProperty("jcifs.smb.client.loadBalancingStrategy", "least_loaded");
        props.setProperty("jcifs.smb.client.channelHealthCheckInterval", "15");

        PropertyConfiguration config = new PropertyConfiguration(props);

        assertTrue(config.isUseMultiChannel());
        assertEquals(6, config.getMaxChannels());
        assertEquals(2, config.getChannelBindingPolicy());
        assertEquals("least_loaded", config.getLoadBalancingStrategy());
        assertEquals(15, config.getChannelHealthCheckInterval());
    }

    @Test
    void testConfigurationInheritance() throws CIFSException {
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.useMultiChannel", "true");
        props.setProperty("jcifs.smb.client.maxChannels", "8");

        PropertyConfiguration config = new PropertyConfiguration(props);

        // Properties set should override defaults
        assertTrue(config.isUseMultiChannel());
        assertEquals(8, config.getMaxChannels());

        // Unset properties should use defaults
        assertEquals(1, config.getChannelBindingPolicy());
        assertEquals("adaptive", config.getLoadBalancingStrategy());
        assertEquals(10, config.getChannelHealthCheckInterval());
    }

    @Test
    void testInvalidPropertyValues() throws CIFSException {
        Properties props = new Properties();

        // Invalid boolean should default to true
        props.setProperty("jcifs.smb.client.useMultiChannel", "invalid");
        PropertyConfiguration config = new PropertyConfiguration(props);
        assertTrue(config.isUseMultiChannel());

        // Invalid integer should use default
        props.clear();
        props.setProperty("jcifs.smb.client.maxChannels", "invalid");
        config = new PropertyConfiguration(props);
        assertEquals(4, config.getMaxChannels());

        // Invalid channel binding policy should default to preferred
        props.clear();
        props.setProperty("jcifs.smb.client.channelBindingPolicy", "invalid");
        config = new PropertyConfiguration(props);
        assertEquals(1, config.getChannelBindingPolicy());
    }

    @Test
    void testEdgeCaseValues() throws CIFSException {
        Properties props = new Properties();

        // Test zero and negative values
        props.setProperty("jcifs.smb.client.maxChannels", "0");
        PropertyConfiguration config = new PropertyConfiguration(props);
        assertEquals(4, config.getMaxChannels()); // Should use default when 0

        props.setProperty("jcifs.smb.client.maxChannels", "-1");
        config = new PropertyConfiguration(props);
        assertEquals(4, config.getMaxChannels()); // Should use default for negative

        props.setProperty("jcifs.smb.client.channelHealthCheckInterval", "0");
        config = new PropertyConfiguration(props);
        assertEquals(10, config.getChannelHealthCheckInterval()); // Should use default when 0
    }
}
