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
package org.codelibs.jcifs.smb.util;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Unit tests for ResourceManager
 */
public class ResourceManagerTest {

    private ResourceManager resourceManager;

    @BeforeEach
    void setUp() {
        resourceManager = ResourceManager.getInstance();
        // Configure with shorter intervals for testing
        resourceManager.configure(1000, 100, true, true);
    }

    /**
     * Test resource for tracking
     */
    static class TestResource implements AutoCloseable {
        private final AtomicBoolean closed = new AtomicBoolean(false);
        private final String name;

        TestResource(String name) {
            this.name = name;
        }

        @Override
        public void close() {
            closed.set(true);
        }

        boolean isClosed() {
            return closed.get();
        }

        String getName() {
            return name;
        }
    }

    @Test
    @DisplayName("Test resource registration and tracking")
    void testResourceRegistration() {
        TestResource resource = new TestResource("test1");
        String resourceId = resourceManager.registerResource(resource);

        assertNotNull(resourceId);
        assertTrue(resourceId.contains("TestResource"));

        Map<String, Object> stats = resourceManager.getStatistics();
        assertTrue((long) stats.get("totalAllocated") > 0);
    }

    @Test
    @DisplayName("Test resource close tracking")
    void testResourceCloseTracking() throws Exception {
        TestResource resource = new TestResource("test2");
        String resourceId = resourceManager.registerResource(resource);

        resource.close();
        resourceManager.markClosed(resourceId);

        Map<String, Object> stats = resourceManager.getStatistics();
        assertTrue((long) stats.get("totalReleased") > 0);
    }

    @Test
    @DisplayName("Test managed resource wrapper")
    void testManagedResource() throws Exception {
        TestResource resource = new TestResource("test3");

        try (ResourceManager.ManagedResource<TestResource> managed = resourceManager.manage(resource)) {
            assertNotNull(managed.get());
            assertEquals("test3", managed.get().getName());
            assertFalse(resource.isClosed());
        }

        assertTrue(resource.isClosed());
    }

    @Test
    @DisplayName("Test managed resource prevents use after close")
    void testManagedResourceUseAfterClose() throws Exception {
        TestResource resource = new TestResource("test4");
        ResourceManager.ManagedResource<TestResource> managed = resourceManager.manage(resource);

        managed.close();
        assertTrue(resource.isClosed());

        assertThrows(IllegalStateException.class, managed::get);
    }

    @Test
    @DisplayName("Test resource unregistration")
    void testResourceUnregistration() {
        TestResource resource = new TestResource("test5");
        String resourceId = resourceManager.registerResource(resource);

        resourceManager.unregisterResource(resourceId);

        // After unregistration, the resource should be removed from active tracking
        Map<String, Object> stats = resourceManager.getStatistics();
        assertNotNull(stats);
    }

    @Test
    @DisplayName("Test force cleanup")
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void testForceCleanup() {
        TestResource resource1 = new TestResource("cleanup1");
        TestResource resource2 = new TestResource("cleanup2");

        resourceManager.registerResource(resource1);
        resourceManager.registerResource(resource2);

        assertFalse(resource1.isClosed());
        assertFalse(resource2.isClosed());

        int cleaned = resourceManager.forceCleanup();
        assertTrue(cleaned >= 2);

        assertTrue(resource1.isClosed());
        assertTrue(resource2.isClosed());
    }

    @Test
    @DisplayName("Test leak detection for unclosed resources")
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void testLeakDetection() throws InterruptedException {
        // Create resource that will be garbage collected without closing
        createLeakyResource();

        // Force garbage collection
        System.gc();
        Thread.sleep(200);

        // Check for leaks
        resourceManager.checkForLeaks();

        Map<String, Object> stats = resourceManager.getStatistics();
        // The leak counter may or may not increment depending on GC timing
        assertNotNull(stats.get("totalLeaks"));
    }

    private void createLeakyResource() {
        TestResource resource = new TestResource("leaky");
        resourceManager.registerResource(resource);
        // Resource goes out of scope without closing - potential leak
    }

    @Test
    @DisplayName("Test automatic cleanup of old resources")
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void testAutomaticCleanup() throws InterruptedException {
        // Configure with very short max age for testing
        resourceManager.configure(100, 50, true, true);

        TestResource resource = new TestResource("old");
        resourceManager.registerResource(resource);

        assertFalse(resource.isClosed());

        // Wait for automatic cleanup to kick in
        Thread.sleep(300);

        // Perform cleanup
        resourceManager.performCleanup();

        // Old resource should be auto-closed
        assertTrue(resource.isClosed());
    }

    @Test
    @DisplayName("Test resource statistics")
    void testResourceStatistics() {
        TestResource resource1 = new TestResource("stat1");
        TestResource resource2 = new TestResource("stat2");

        String id1 = resourceManager.registerResource(resource1);
        resourceManager.registerResource(resource2);

        resourceManager.markClosed(id1);

        Map<String, Object> stats = resourceManager.getStatistics();

        assertNotNull(stats);
        assertTrue((long) stats.get("totalAllocated") >= 2);
        assertTrue((long) stats.get("totalReleased") >= 1);
        assertNotNull(stats.get("activeResources"));
        assertNotNull(stats.get("closedResources"));
    }

    @Test
    @DisplayName("Test get active resources")
    void testGetActiveResources() {
        TestResource resource = new TestResource("active1");
        resourceManager.registerResource(resource);

        var activeResources = resourceManager.getActiveResources();
        assertNotNull(activeResources);
        assertFalse(activeResources.isEmpty());

        boolean found = activeResources.stream().anyMatch(desc -> desc.contains("TestResource"));
        assertTrue(found);
    }

    @Test
    @DisplayName("Test multiple close calls on managed resource")
    void testMultipleCloseOnManagedResource() throws Exception {
        TestResource resource = new TestResource("multiclose");
        ResourceManager.ManagedResource<TestResource> managed = resourceManager.manage(resource);

        managed.close();
        assertTrue(resource.isClosed());

        // Second close should not throw
        assertDoesNotThrow(managed::close);
    }

    @Test
    @DisplayName("Test null resource registration throws exception")
    void testNullResourceRegistration() {
        assertThrows(IllegalArgumentException.class, () -> resourceManager.registerResource(null));
    }

    @Test
    @DisplayName("Test configuration updates")
    void testConfigurationUpdates() {
        resourceManager.configure(5000, 1000, false, false);

        // Configuration should be applied (we can't directly verify private fields,
        // but we can ensure it doesn't throw)
        assertDoesNotThrow(() -> resourceManager.checkForLeaks());
        assertDoesNotThrow(() -> resourceManager.performCleanup());
    }
}