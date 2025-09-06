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
package org.codelibs.jcifs.smb.internal.smb2.lease;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for DirectoryCacheEntry
 */
public class DirectoryCacheEntryTest {

    private DirectoryCacheEntry entry;
    private Smb2LeaseKey leaseKey;
    private String directoryPath = "/test/dir";

    @BeforeEach
    public void setUp() {
        leaseKey = new Smb2LeaseKey();
        entry = new DirectoryCacheEntry(directoryPath, leaseKey, DirectoryCacheScope.IMMEDIATE_CHILDREN);
    }

    @Test
    public void testConstructor() {
        assertEquals(directoryPath, entry.getDirectoryPath());
        assertEquals(leaseKey, entry.getLeaseKey());
        assertEquals(DirectoryCacheScope.IMMEDIATE_CHILDREN, entry.getScope());
        assertFalse(entry.isComplete());
        assertFalse(entry.hasChanges());
        assertTrue(entry.getChildren().isEmpty());
    }

    @Test
    public void testUpdateChild() {
        String childName = "file1.txt";
        long size = 1024L;
        long lastModified = System.currentTimeMillis();
        boolean isDirectory = false;
        long attributes = 0x20; // FILE_ATTRIBUTE_ARCHIVE
        long creationTime = System.currentTimeMillis() - 10000;
        long lastAccessTime = System.currentTimeMillis() - 5000;

        entry.updateChild(childName, size, lastModified, isDirectory, attributes, creationTime, lastAccessTime);

        assertTrue(entry.hasChild(childName));
        assertEquals(1, entry.getChildren().size());

        DirectoryCacheEntry.FileInfo fileInfo = entry.getChild(childName);
        assertNotNull(fileInfo);
        assertEquals(childName, fileInfo.getName());
        assertEquals(size, fileInfo.getSize());
        assertEquals(lastModified, fileInfo.getLastModified());
        assertEquals(isDirectory, fileInfo.isDirectory());
        assertEquals(attributes, fileInfo.getAttributes());
        assertEquals(creationTime, fileInfo.getCreationTime());
        assertEquals(lastAccessTime, fileInfo.getLastAccessTime());
    }

    @Test
    public void testUpdateExistingChild() {
        String childName = "file1.txt";

        // Initial update - should mark as changed
        entry.updateChild(childName, 1024L, 1000L, false, 0x20, 500L, 800L);
        assertTrue(entry.hasChanges());

        // Clear changes to test next scenario
        entry.markComplete();
        assertFalse(entry.hasChanges());

        // Update with same values - should not mark as changed (no actual change)
        entry.updateChild(childName, 1024L, 1000L, false, 0x20, 500L, 800L);
        assertFalse(entry.hasChanges());

        // Update with different values - should mark as changed
        entry.updateChild(childName, 2048L, 2000L, false, 0x20, 500L, 800L);
        assertTrue(entry.hasChanges());
    }

    @Test
    public void testRemoveChild() {
        String childName = "file1.txt";

        // Add a child
        entry.updateChild(childName, 1024L, 1000L, false, 0x20, 500L, 800L);
        assertTrue(entry.hasChild(childName));

        // Remove the child
        entry.removeChild(childName);
        assertFalse(entry.hasChild(childName));
        assertTrue(entry.hasChanges());

        // Remove non-existent child - should not change state
        entry.removeChild("nonexistent.txt");
        assertTrue(entry.hasChanges()); // Still has changes from previous removal
    }

    @Test
    public void testGetChildren() {
        // Add multiple children
        entry.updateChild("file1.txt", 1024L, 1000L, false, 0x20, 500L, 800L);
        entry.updateChild("file2.txt", 2048L, 2000L, false, 0x20, 600L, 900L);
        entry.updateChild("dir1", 0L, 3000L, true, 0x10, 700L, 1000L);

        List<DirectoryCacheEntry.FileInfo> children = entry.getChildren();
        assertEquals(3, children.size());

        // Verify all children are present
        assertTrue(children.stream().anyMatch(f -> "file1.txt".equals(f.getName())));
        assertTrue(children.stream().anyMatch(f -> "file2.txt".equals(f.getName())));
        assertTrue(children.stream().anyMatch(f -> "dir1".equals(f.getName())));
    }

    @Test
    public void testMarkComplete() {
        entry.updateChild("file1.txt", 1024L, 1000L, false, 0x20, 500L, 800L);
        assertTrue(entry.hasChanges());
        assertFalse(entry.isComplete());

        entry.markComplete();

        assertTrue(entry.isComplete());
        assertFalse(entry.hasChanges()); // Changes are cleared when marked complete
    }

    @Test
    public void testInvalidate() {
        // Add some children
        entry.updateChild("file1.txt", 1024L, 1000L, false, 0x20, 500L, 800L);
        entry.updateChild("file2.txt", 2048L, 2000L, false, 0x20, 600L, 900L);
        entry.markComplete();

        // Invalidate the cache
        entry.invalidate();

        assertFalse(entry.isComplete());
        assertTrue(entry.hasChanges());
        assertTrue(entry.getChildren().isEmpty());
    }

    @Test
    public void testExpiration() {
        // Set a very short max age
        entry.setMaxAge(100); // 100ms

        assertFalse(entry.isExpired());
        assertFalse(entry.needsRefresh());

        // Wait for expiration
        try {
            Thread.sleep(150);
        } catch (InterruptedException e) {
            // Ignore
        }

        assertTrue(entry.isExpired());
        assertTrue(entry.needsRefresh());
    }

    @Test
    public void testNeedsRefresh() {
        assertFalse(entry.needsRefresh());

        // Mark as having changes
        entry.updateChild("file1.txt", 1024L, 1000L, false, 0x20, 500L, 800L);
        assertTrue(entry.hasChanges());
        assertTrue(entry.needsRefresh());

        // Mark as complete (clears changes)
        entry.markComplete();
        assertFalse(entry.needsRefresh());
    }

    @Test
    public void testInconsistencyCount() {
        assertEquals(0, entry.getInconsistencyCount());
        assertEquals(1, entry.getInconsistencyCount());
        assertEquals(2, entry.getInconsistencyCount());

        entry.resetInconsistencyCount();
        assertEquals(0, entry.getInconsistencyCount());
    }

    @Test
    public void testFileInfoMatches() {
        DirectoryCacheEntry.FileInfo fileInfo = new DirectoryCacheEntry.FileInfo("test.txt", 1024L, 1000L, false, 0x20, 500L, 800L);

        // Should match with same values
        assertTrue(fileInfo.matches(1024L, 1000L, 0x20));

        // Should not match with different size
        assertFalse(fileInfo.matches(2048L, 1000L, 0x20));

        // Should not match with different last modified
        assertFalse(fileInfo.matches(1024L, 2000L, 0x20));

        // Should not match with different attributes
        assertFalse(fileInfo.matches(1024L, 1000L, 0x10));
    }

    @Test
    public void testThreadSafety() throws InterruptedException {
        // Test concurrent updates from multiple threads
        Thread[] threads = new Thread[10];

        for (int i = 0; i < threads.length; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                for (int j = 0; j < 100; j++) {
                    String name = "file" + index + "_" + j + ".txt";
                    entry.updateChild(name, j * 100L, j * 1000L, false, 0x20, j * 500L, j * 800L);
                }
            });
            threads[i].start();
        }

        // Wait for all threads to complete
        for (Thread thread : threads) {
            thread.join();
        }

        // Verify all entries were added
        assertEquals(1000, entry.getChildren().size());
    }
}