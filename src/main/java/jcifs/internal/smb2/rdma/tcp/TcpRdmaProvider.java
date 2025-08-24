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
package jcifs.internal.smb2.rdma.tcp;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.EnumSet;
import java.util.Set;

import jcifs.internal.smb2.rdma.RdmaAccess;
import jcifs.internal.smb2.rdma.RdmaCapability;
import jcifs.internal.smb2.rdma.RdmaConnection;
import jcifs.internal.smb2.rdma.RdmaMemoryRegion;
import jcifs.internal.smb2.rdma.RdmaProvider;

/**
 * TCP fallback RDMA provider.
 *
 * This provider uses regular TCP connections but maintains the RDMA
 * interface for compatibility. It only supports send/receive operations
 * and does not provide true RDMA read/write capabilities.
 */
public class TcpRdmaProvider implements RdmaProvider {

    /**
     * Creates a new TCP RDMA provider instance
     */
    public TcpRdmaProvider() {
        // Default constructor
    }

    @Override
    public boolean isAvailable() {
        return true; // TCP is always available
    }

    @Override
    public Set<RdmaCapability> getSupportedCapabilities() {
        // TCP fallback only supports send/receive
        return EnumSet.of(RdmaCapability.RDMA_SEND_RECEIVE);
    }

    @Override
    public RdmaConnection createConnection(InetSocketAddress remote, InetSocketAddress local) throws IOException {
        return new TcpRdmaConnection(remote, local);
    }

    @Override
    public RdmaConnection connect(String hostname, int port) throws IOException {
        InetSocketAddress remoteAddress = new InetSocketAddress(hostname, port);
        RdmaConnection connection = createConnection(remoteAddress, null);
        connection.connect();
        return connection;
    }

    @Override
    public RdmaMemoryRegion registerMemory(ByteBuffer buffer, EnumSet<RdmaAccess> access) throws IOException {
        // TCP doesn't need real memory registration
        return new TcpMemoryRegion(buffer, access);
    }

    @Override
    public String getProviderName() {
        return "TCP Fallback";
    }

    @Override
    public int getMaxMessageSize() {
        return 65536; // 64KB for TCP
    }

    @Override
    public void shutdown() {
        // Nothing to clean up for TCP
    }
}
