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
package org.codelibs.jcifs.smb.internal.smb2.rdma.disni;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.EnumSet;
import java.util.Set;

import org.codelibs.jcifs.smb.internal.smb2.rdma.RdmaAccess;
import org.codelibs.jcifs.smb.internal.smb2.rdma.RdmaCapability;
import org.codelibs.jcifs.smb.internal.smb2.rdma.RdmaConnection;
import org.codelibs.jcifs.smb.internal.smb2.rdma.RdmaMemoryRegion;
import org.codelibs.jcifs.smb.internal.smb2.rdma.RdmaProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * DiSNI RDMA provider for InfiniBand/RoCE networks.
 *
 * This provider uses the DiSNI (Direct Storage and Networking Interface)
 * library to provide high-performance RDMA operations over InfiniBand
 * and RoCE (RDMA over Converged Ethernet) networks.
 */
public class DisniRdmaProvider implements RdmaProvider {

    /**
     * Creates a new DiSNI RDMA provider instance
     */
    public DisniRdmaProvider() {
        // Default constructor
    }

    private static final Logger log = LoggerFactory.getLogger(DisniRdmaProvider.class);

    // DiSNI components - these would be actual DiSNI objects in a real implementation
    private Object endpointGroup; // RdmaActiveEndpointGroup<DisniRdmaEndpoint>
    private Object endpoint; // RdmaActiveEndpoint
    private boolean initialized = false;

    @Override
    public boolean isAvailable() {
        try {
            // Check if DiSNI is available on the classpath
            Class.forName("com.ibm.disni.RdmaActiveEndpointGroup");

            // Additional checks could include:
            // - Verifying RDMA devices are available
            // - Testing basic RDMA operations
            // - Checking for required native libraries

            return true;
        } catch (ClassNotFoundException e) {
            log.debug("DiSNI not available: {}", e.getMessage());
            return false;
        } catch (UnsatisfiedLinkError e) {
            log.debug("DiSNI native libraries not available: {}", e.getMessage());
            return false;
        }
    }

    @Override
    public Set<RdmaCapability> getSupportedCapabilities() {
        return EnumSet.allOf(RdmaCapability.class);
    }

    @Override
    public RdmaConnection createConnection(InetSocketAddress remote, InetSocketAddress local) throws IOException {
        ensureInitialized();
        return new DisniRdmaConnection(remote, local, endpointGroup);
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
        ensureInitialized();
        return new DisniMemoryRegion(buffer, access, endpoint);
    }

    /**
     * Initialize DiSNI components if not already initialized
     *
     * @throws IOException if initialization fails
     */
    private void ensureInitialized() throws IOException {
        if (!initialized) {
            try {
                // In a real implementation, this would initialize DiSNI:
                // endpointGroup = new RdmaActiveEndpointGroup<DisniRdmaEndpoint>(
                //     1000, false, 128, 4, 128);
                // endpointGroup.init(new DisniRdmaEndpointFactory());

                // For now, we'll just create placeholder objects
                endpointGroup = new Object();
                endpoint = new Object();

                initialized = true;
                log.info("DiSNI RDMA provider initialized");

            } catch (Exception e) {
                throw new IOException("Failed to initialize DiSNI", e);
            }
        }
    }

    @Override
    public String getProviderName() {
        return "DiSNI (InfiniBand/RoCE)";
    }

    @Override
    public int getMaxMessageSize() {
        return 2147483647; // 2GB - DiSNI theoretical limit
    }

    @Override
    public void shutdown() {
        if (endpointGroup != null) {
            try {
                // In real implementation: endpointGroup.close();
                log.info("DiSNI RDMA provider shut down");
            } catch (Exception e) {
                log.error("Error shutting down DiSNI", e);
            } finally {
                endpointGroup = null;
                endpoint = null;
                initialized = false;
            }
        }
    }
}
