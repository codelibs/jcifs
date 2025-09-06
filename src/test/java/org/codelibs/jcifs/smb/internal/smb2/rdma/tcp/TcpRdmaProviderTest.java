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
package org.codelibs.jcifs.smb.internal.smb2.rdma.tcp;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.EnumSet;
import java.util.Set;

import org.codelibs.jcifs.smb.internal.smb2.rdma.RdmaAccess;
import org.codelibs.jcifs.smb.internal.smb2.rdma.RdmaCapability;
import org.codelibs.jcifs.smb.internal.smb2.rdma.RdmaConnection;
import org.codelibs.jcifs.smb.internal.smb2.rdma.RdmaMemoryRegion;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for TCP RDMA provider
 */
public class TcpRdmaProviderTest {

    private TcpRdmaProvider provider;

    @BeforeEach
    public void setUp() {
        provider = new TcpRdmaProvider();
    }

    @Test
    public void testIsAvailable() {
        assertTrue(provider.isAvailable(), "TCP provider should always be available");
    }

    @Test
    public void testGetSupportedCapabilities() {
        Set<RdmaCapability> capabilities = provider.getSupportedCapabilities();
        assertNotNull(capabilities, "Capabilities should not be null");
        assertEquals(1, capabilities.size(), "TCP provider should only support send/receive");
        assertTrue(capabilities.contains(RdmaCapability.RDMA_SEND_RECEIVE), "Should support send/receive");
        assertFalse(capabilities.contains(RdmaCapability.RDMA_READ), "Should not support RDMA read");
        assertFalse(capabilities.contains(RdmaCapability.RDMA_WRITE), "Should not support RDMA write");
    }

    @Test
    public void testCreateConnection() throws Exception {
        InetSocketAddress remote = new InetSocketAddress("localhost", 445);
        InetSocketAddress local = null;

        RdmaConnection connection = provider.createConnection(remote, local);
        assertNotNull(connection, "Connection should not be null");
        assertEquals(remote, connection.getRemoteAddress(), "Remote address should match");
    }

    @Test
    public void testRegisterMemory() throws Exception {
        ByteBuffer buffer = ByteBuffer.allocateDirect(1024);
        EnumSet<RdmaAccess> access = EnumSet.of(RdmaAccess.LOCAL_READ, RdmaAccess.LOCAL_WRITE);

        RdmaMemoryRegion region = provider.registerMemory(buffer, access);
        assertNotNull(region, "Memory region should not be null");
        assertEquals(buffer, region.getBuffer(), "Buffer should match");
        assertEquals(1024, region.getSize(), "Size should match buffer size");
        assertTrue(region.hasAccess(RdmaAccess.LOCAL_READ), "Should have local read access");
        assertTrue(region.hasAccess(RdmaAccess.LOCAL_WRITE), "Should have local write access");
        assertFalse(region.hasAccess(RdmaAccess.REMOTE_READ), "Should not have remote read access");

        // Test cleanup
        region.close();
        assertFalse(region.isValid(), "Region should be invalid after close");
    }

    @Test
    public void testGetProviderName() {
        assertEquals("TCP Fallback", provider.getProviderName());
    }

    @Test
    public void testGetMaxMessageSize() {
        assertEquals(65536, provider.getMaxMessageSize(), "TCP provider should have 64KB limit");
    }

    @Test
    public void testShutdown() {
        // Should not throw exception
        assertDoesNotThrow(() -> provider.shutdown());
    }
}
