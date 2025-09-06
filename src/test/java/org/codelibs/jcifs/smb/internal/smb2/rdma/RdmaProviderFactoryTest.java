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
package org.codelibs.jcifs.smb.internal.smb2.rdma;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for RdmaProviderFactory
 */
public class RdmaProviderFactoryTest {

    @Test
    public void testCreateProviderAuto() {
        RdmaProvider provider = RdmaProviderFactory.createProvider("auto");
        assertNotNull(provider, "Auto provider selection should return a provider");
        assertTrue(provider.isAvailable(), "Returned provider should be available");
    }

    @Test
    public void testCreateProviderTcp() {
        RdmaProvider provider = RdmaProviderFactory.createProvider("tcp");
        assertNotNull(provider, "TCP provider should always be available");
        assertTrue(provider.isAvailable(), "TCP provider should be available");
        assertEquals("TCP Fallback", provider.getProviderName());
    }

    @Test
    public void testCreateProviderDisni() {
        RdmaProvider provider = RdmaProviderFactory.createProvider("disni");
        // DiSNI may or may not be available depending on system configuration
        if (provider != null) {
            assertTrue(provider.isAvailable(), "If DiSNI provider is returned, it should be available");
            assertEquals("DiSNI (InfiniBand/RoCE)", provider.getProviderName());
        }
    }

    @Test
    public void testCreateProviderUnknown() {
        RdmaProvider provider = RdmaProviderFactory.createProvider("unknown");
        assertNull(provider, "Unknown provider should return null");
    }

    @Test
    public void testSelectBestProvider() {
        RdmaProvider provider = RdmaProviderFactory.selectBestProvider();
        assertNotNull(provider, "Should always return at least TCP provider");
        assertTrue(provider.isAvailable(), "Selected provider should be available");
    }

    @Test
    public void testIsRdmaAvailable() {
        assertTrue(RdmaProviderFactory.isRdmaAvailable(), "RDMA should be available (at least TCP fallback)");
    }

    @Test
    public void testGetAvailableProviders() {
        List<String> providers = RdmaProviderFactory.getAvailableProviders();
        assertNotNull(providers, "Available providers list should not be null");
        assertFalse(providers.isEmpty(), "Should have at least one available provider");
        assertTrue(providers.contains("TCP Fallback"), "Should include TCP fallback");
    }
}
