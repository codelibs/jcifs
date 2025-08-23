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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.EnumSet;
import java.util.Set;

/**
 * Interface for RDMA provider implementations.
 *
 * This interface abstracts different RDMA implementations such as
 * InfiniBand, iWARP, RoCE, or TCP fallback providers.
 */
public interface RdmaProvider {

    /**
     * Check if RDMA is available on this system
     *
     * @return true if RDMA can be used, false otherwise
     */
    boolean isAvailable();

    /**
     * Get supported RDMA capabilities
     *
     * @return set of capabilities supported by this provider
     */
    Set<RdmaCapability> getSupportedCapabilities();

    /**
     * Create RDMA connection to remote endpoint
     *
     * @param remote remote socket address
     * @param local local socket address, may be null for auto-binding
     * @return new RDMA connection instance
     * @throws IOException if connection creation fails
     */
    RdmaConnection createConnection(InetSocketAddress remote, InetSocketAddress local) throws IOException;

    /**
     * Connect to a remote RDMA endpoint
     *
     * @param hostname remote hostname or IP address
     * @param port remote port number
     * @return established RDMA connection
     * @throws IOException if connection fails
     */
    RdmaConnection connect(String hostname, int port) throws IOException;

    /**
     * Register memory region for RDMA operations
     *
     * @param buffer memory buffer to register
     * @param access access permissions for the memory region
     * @return registered memory region
     * @throws IOException if memory registration fails
     */
    RdmaMemoryRegion registerMemory(ByteBuffer buffer, EnumSet<RdmaAccess> access) throws IOException;

    /**
     * Get provider name (e.g., "InfiniBand", "iWARP", "RoCE", "TCP Fallback")
     *
     * @return human-readable provider name
     */
    String getProviderName();

    /**
     * Get maximum message size supported by this provider
     *
     * @return maximum message size in bytes
     */
    int getMaxMessageSize();

    /**
     * Clean up provider resources
     *
     * This method should be called when the provider is no longer needed
     * to release any system resources.
     */
    void shutdown();
}
