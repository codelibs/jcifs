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

import java.nio.ByteBuffer;
import java.util.EnumSet;
import java.util.concurrent.atomic.AtomicInteger;

import jcifs.internal.smb2.rdma.RdmaAccess;
import jcifs.internal.smb2.rdma.RdmaMemoryRegion;

/**
 * TCP memory region implementation.
 *
 * For TCP fallback, memory regions are just wrappers around
 * ByteBuffers since no real RDMA registration is needed.
 */
public class TcpMemoryRegion extends RdmaMemoryRegion {

    private static final AtomicInteger keyGenerator = new AtomicInteger(1000);

    /**
     * Create new TCP memory region
     *
     * @param buffer memory buffer
     * @param access access permissions (ignored for TCP)
     */
    public TcpMemoryRegion(ByteBuffer buffer, EnumSet<RdmaAccess> access) {
        super(buffer, access);
    }

    @Override
    public void invalidate() {
        // No real invalidation needed for TCP
        valid = false;
    }

    @Override
    protected int generateLocalKey() {
        return keyGenerator.getAndIncrement();
    }

    @Override
    protected int generateRemoteKey() {
        return keyGenerator.getAndIncrement();
    }

    @Override
    protected long getBufferAddress(ByteBuffer buffer) {
        // Return a fake address for TCP
        // In real RDMA implementations, this would be the native memory address
        return buffer.hashCode();
    }
}
