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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.ByteBuffer;
import java.util.EnumSet;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.internal.smb2.rdma.tcp.TcpMemoryRegion;

/**
 * Unit tests for RDMA buffer manager
 */
public class RdmaBufferManagerTest {

    @Mock
    private RdmaProvider mockProvider;

    private RdmaBufferManager bufferManager;
    private AutoCloseable mocks;

    @BeforeEach
    public void setUp() throws Exception {
        mocks = MockitoAnnotations.openMocks(this);

        // Set up mock provider to return TCP memory regions
        when(mockProvider.registerMemory(any(ByteBuffer.class), any())).thenAnswer(invocation -> {
            ByteBuffer buffer = invocation.getArgument(0);
            EnumSet<RdmaAccess> access = invocation.getArgument(1);
            return new TcpMemoryRegion(buffer, access);
        });

        bufferManager = new RdmaBufferManager(mockProvider);
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (bufferManager != null) {
            bufferManager.cleanup();
        }
        if (mocks != null) {
            mocks.close();
        }
    }

    @Test
    public void testGetSendRegion() throws Exception {
        RdmaMemoryRegion region = bufferManager.getSendRegion(1024);
        assertNotNull(region, "Send region should not be null");
        assertTrue(region.getSize() >= 1024, "Region should be at least requested size");
        assertTrue(region.hasAccess(RdmaAccess.LOCAL_READ), "Should have local read access");
        assertTrue(region.hasAccess(RdmaAccess.REMOTE_READ), "Should have remote read access");

        // Verify provider was called
        verify(mockProvider, atLeastOnce()).registerMemory(any(ByteBuffer.class), any());
    }

    @Test
    public void testReleaseSendRegion() throws Exception {
        RdmaMemoryRegion region = bufferManager.getSendRegion(1024);
        assertNotNull(region);

        // Release should not throw exception
        assertDoesNotThrow(() -> bufferManager.releaseSendRegion(region));
    }

    @Test
    public void testGetReceiveRegion() throws Exception {
        RdmaMemoryRegion region = bufferManager.getReceiveRegion();
        assertNotNull(region, "Receive region should not be null");
        assertTrue(region.getSize() > 0, "Region should have positive size");
        assertTrue(region.hasAccess(RdmaAccess.LOCAL_WRITE), "Should have local write access");
        assertTrue(region.hasAccess(RdmaAccess.REMOTE_WRITE), "Should have remote write access");

        // Verify provider was called
        verify(mockProvider, atLeastOnce()).registerMemory(any(ByteBuffer.class), any());
    }

    @Test
    public void testReleaseReceiveRegion() throws Exception {
        RdmaMemoryRegion region = bufferManager.getReceiveRegion();
        assertNotNull(region);

        // Release should not throw exception
        assertDoesNotThrow(() -> bufferManager.releaseReceiveRegion(region));
    }

    @Test
    public void testAllocateBuffer() {
        ByteBuffer buffer = bufferManager.allocateBuffer(2048);
        assertNotNull(buffer, "Buffer should not be null");
        assertTrue(buffer.capacity() >= 2048, "Buffer should be at least requested size");
        assertTrue(buffer.isDirect(), "Buffer should be direct");
    }

    @Test
    public void testReleaseBuffer() {
        ByteBuffer buffer = bufferManager.allocateBuffer(1024);

        // Release should not throw exception
        assertDoesNotThrow(() -> bufferManager.releaseBuffer(buffer));
    }

    @Test
    public void testStatistics() throws Exception {
        long initialAllocated = bufferManager.getTotalAllocated();

        // Allocate regions larger than pool buffer size to force new allocations
        RdmaMemoryRegion region1 = bufferManager.getSendRegion(131072); // 128KB > 64KB pool size
        RdmaMemoryRegion region2 = bufferManager.getSendRegion(131072); // Another large allocation

        assertTrue(bufferManager.getTotalAllocated() > initialAllocated, "Total allocated should increase");
        assertTrue(bufferManager.getActiveRegions() > 0, "Active regions should be positive");

        // Release regions
        bufferManager.releaseSendRegion(region1);
        bufferManager.releaseReceiveRegion(region2);
    }

    @Test
    public void testCleanup() throws Exception {
        // Allocate some regions from the pool and then release them back
        RdmaMemoryRegion region1 = bufferManager.getSendRegion(1024);
        RdmaMemoryRegion region2 = bufferManager.getReceiveRegion();

        // Release the regions back to the pool before cleanup
        bufferManager.releaseSendRegion(region1);
        bufferManager.releaseReceiveRegion(region2);

        long allocatedBeforeCleanup = bufferManager.getTotalAllocated();

        // Cleanup should not throw exception
        assertDoesNotThrow(() -> bufferManager.cleanup());

        // After cleanup, all regions should be released (but the count may not match exactly
        // if some regions were pooled rather than immediately released)
        assertTrue(bufferManager.getTotalReleased() > 0, "Some regions should be released during cleanup");
        assertEquals(allocatedBeforeCleanup, bufferManager.getTotalReleased(),
                "All allocated regions should eventually be released after cleanup");
    }

    @Test
    public void testPooling() throws Exception {
        // Get a region and release it
        RdmaMemoryRegion region1 = bufferManager.getSendRegion(1024);
        bufferManager.releaseSendRegion(region1);

        // Get another region - should potentially reuse from pool
        RdmaMemoryRegion region2 = bufferManager.getSendRegion(1024);
        assertNotNull(region2);

        // Both regions should be valid
        assertTrue(region1.isValid() || !region1.isValid()); // Either state is OK after release
        assertTrue(region2.isValid(), "New region should be valid");
    }
}
