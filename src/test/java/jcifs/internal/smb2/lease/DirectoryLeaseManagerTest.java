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
package jcifs.internal.smb2.lease;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.smb.SmbFile;

/**
 * Unit tests for DirectoryLeaseManager
 */
public class DirectoryLeaseManagerTest {

    @Mock
    private CIFSContext context;

    @Mock
    private Configuration config;

    @Mock
    private LeaseManager baseLeaseManager;

    @Mock
    private SmbFile mockFile1;

    @Mock
    private SmbFile mockFile2;

    private DirectoryLeaseManager directoryLeaseManager;
    private AutoCloseable mocks;

    @BeforeEach
    public void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        when(context.getConfig()).thenReturn(config);
        when(config.isDirectoryNotificationsEnabled()).thenReturn(false); // Disable for unit tests

        directoryLeaseManager = new DirectoryLeaseManager(context, baseLeaseManager);
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (directoryLeaseManager != null) {
            directoryLeaseManager.shutdown();
        }
        if (mocks != null) {
            mocks.close();
        }
    }

    @Test
    public void testRequestDirectoryLease() {
        String directoryPath = "/test/dir";
        int requestedState = DirectoryLeaseState.DIRECTORY_READ_HANDLE;
        DirectoryCacheScope scope = DirectoryCacheScope.IMMEDIATE_CHILDREN;
        Smb2LeaseKey expectedKey = new Smb2LeaseKey();

        when(baseLeaseManager.requestLease(directoryPath, requestedState)).thenReturn(expectedKey);

        Smb2LeaseKey result = directoryLeaseManager.requestDirectoryLease(directoryPath, requestedState, scope);

        assertEquals(expectedKey, result);
        verify(baseLeaseManager).requestLease(directoryPath, requestedState);

        // Verify cache entry was created
        DirectoryCacheEntry cacheEntry = directoryLeaseManager.getCacheEntry(directoryPath);
        assertNotNull(cacheEntry);
        assertEquals(directoryPath, cacheEntry.getDirectoryPath());
        assertEquals(expectedKey, cacheEntry.getLeaseKey());
        assertEquals(scope, cacheEntry.getScope());
    }

    @Test
    public void testGetCacheEntry() {
        String directoryPath = "/test/dir";
        Smb2LeaseKey leaseKey = new Smb2LeaseKey();

        // Initially no cache entry
        assertNull(directoryLeaseManager.getCacheEntry(directoryPath));

        // Request a lease to create cache entry
        when(baseLeaseManager.requestLease(anyString(), anyInt())).thenReturn(leaseKey);
        directoryLeaseManager.requestDirectoryLease(directoryPath, DirectoryLeaseState.DIRECTORY_READ_HANDLE,
                DirectoryCacheScope.IMMEDIATE_CHILDREN);

        // Now cache entry should exist
        DirectoryCacheEntry entry = directoryLeaseManager.getCacheEntry(directoryPath);
        assertNotNull(entry);
        assertEquals(directoryPath, entry.getDirectoryPath());
    }

    @Test
    public void testGetCacheEntryWithExpiredLease() {
        String directoryPath = "/test/dir";
        Smb2LeaseKey leaseKey = new Smb2LeaseKey();

        // Create cache entry
        when(baseLeaseManager.requestLease(anyString(), anyInt())).thenReturn(leaseKey);
        directoryLeaseManager.requestDirectoryLease(directoryPath, DirectoryLeaseState.DIRECTORY_READ_HANDLE,
                DirectoryCacheScope.IMMEDIATE_CHILDREN);

        // Make the cache entry expired
        DirectoryCacheEntry entry = directoryLeaseManager.getCacheEntry(directoryPath);
        entry.setMaxAge(1); // 1ms to expire immediately
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            // Ignore
        }

        // When lease is lost, cache entry should be removed
        when(baseLeaseManager.getLease(leaseKey)).thenReturn(null);

        assertNull(directoryLeaseManager.getCacheEntry(directoryPath));
    }

    @Test
    public void testCanCacheDirectoryListing() {
        String directoryPath = "/test/dir";
        Smb2LeaseKey leaseKey = new Smb2LeaseKey();

        // No cache entry - should return false
        assertFalse(directoryLeaseManager.canCacheDirectoryListing(directoryPath));

        // Create cache entry with read lease
        when(baseLeaseManager.requestLease(anyString(), anyInt())).thenReturn(leaseKey);
        directoryLeaseManager.requestDirectoryLease(directoryPath, DirectoryLeaseState.DIRECTORY_READ_HANDLE,
                DirectoryCacheScope.IMMEDIATE_CHILDREN);

        LeaseManager.LeaseEntry mockLeaseEntry = mock(LeaseManager.LeaseEntry.class);
        when(mockLeaseEntry.hasReadCache()).thenReturn(true);
        when(baseLeaseManager.getLease(leaseKey)).thenReturn(mockLeaseEntry);

        assertTrue(directoryLeaseManager.canCacheDirectoryListing(directoryPath));

        // When read cache is lost
        when(mockLeaseEntry.hasReadCache()).thenReturn(false);
        assertFalse(directoryLeaseManager.canCacheDirectoryListing(directoryPath));
    }

    @Test
    public void testGetCachedDirectoryListing() throws IOException {
        String directoryPath = "/test/dir";
        Smb2LeaseKey leaseKey = new Smb2LeaseKey();

        // Create cache entry
        when(baseLeaseManager.requestLease(anyString(), anyInt())).thenReturn(leaseKey);
        directoryLeaseManager.requestDirectoryLease(directoryPath, DirectoryLeaseState.DIRECTORY_READ_HANDLE,
                DirectoryCacheScope.IMMEDIATE_CHILDREN);

        // No cached listing initially
        assertNull(directoryLeaseManager.getCachedDirectoryListing(directoryPath));

        // Setup mock files
        when(mockFile1.getName()).thenReturn("file1.txt");
        when(mockFile1.length()).thenReturn(1024L);
        when(mockFile1.lastModified()).thenReturn(1000L);
        when(mockFile1.isDirectory()).thenReturn(false);
        when(mockFile1.getAttributes()).thenReturn(0x20);
        when(mockFile1.createTime()).thenReturn(500L);
        when(mockFile1.lastAccess()).thenReturn(800L);

        when(mockFile2.getName()).thenReturn("dir1");
        when(mockFile2.length()).thenReturn(0L);
        when(mockFile2.lastModified()).thenReturn(2000L);
        when(mockFile2.isDirectory()).thenReturn(true);
        when(mockFile2.getAttributes()).thenReturn(0x10);
        when(mockFile2.createTime()).thenReturn(600L);
        when(mockFile2.lastAccess()).thenReturn(900L);

        // Update cache
        List<SmbFile> files = Arrays.asList(mockFile1, mockFile2);
        directoryLeaseManager.updateDirectoryCache(directoryPath, files);

        // Verify cache entry was updated (test the cache content directly)
        DirectoryCacheEntry cacheEntry = directoryLeaseManager.getCacheEntry(directoryPath);
        assertNotNull(cacheEntry);
        assertTrue(cacheEntry.isComplete());
        assertEquals(2, cacheEntry.getChildren().size());

        // Verify the cached files have correct names
        List<DirectoryCacheEntry.FileInfo> children = cacheEntry.getChildren();
        assertTrue(children.stream().anyMatch(f -> "file1.txt".equals(f.getName())));
        assertTrue(children.stream().anyMatch(f -> "dir1".equals(f.getName())));
    }

    @Test
    public void testUpdateDirectoryCache() throws IOException {
        String directoryPath = "/test/dir";
        Smb2LeaseKey leaseKey = new Smb2LeaseKey();

        // Create cache entry
        when(baseLeaseManager.requestLease(anyString(), anyInt())).thenReturn(leaseKey);
        directoryLeaseManager.requestDirectoryLease(directoryPath, DirectoryLeaseState.DIRECTORY_READ_HANDLE,
                DirectoryCacheScope.IMMEDIATE_CHILDREN);

        // Setup mock file
        when(mockFile1.getName()).thenReturn("file1.txt");
        when(mockFile1.length()).thenReturn(1024L);
        when(mockFile1.lastModified()).thenReturn(1000L);
        when(mockFile1.isDirectory()).thenReturn(false);
        when(mockFile1.getAttributes()).thenReturn(0x20);
        when(mockFile1.createTime()).thenReturn(500L);
        when(mockFile1.lastAccess()).thenReturn(800L);

        // Update cache
        List<SmbFile> files = Arrays.asList(mockFile1);
        directoryLeaseManager.updateDirectoryCache(directoryPath, files);

        // Verify cache was updated
        DirectoryCacheEntry entry = directoryLeaseManager.getCacheEntry(directoryPath);
        assertNotNull(entry);
        assertTrue(entry.isComplete());
        assertTrue(entry.hasChild("file1.txt"));
    }

    @Test
    public void testHandleDirectoryChange() {
        String directoryPath = "/test/dir";
        Smb2LeaseKey leaseKey = new Smb2LeaseKey();

        // Create cache entry with some files
        when(baseLeaseManager.requestLease(anyString(), anyInt())).thenReturn(leaseKey);
        directoryLeaseManager.requestDirectoryLease(directoryPath, DirectoryLeaseState.DIRECTORY_READ_HANDLE,
                DirectoryCacheScope.IMMEDIATE_CHILDREN);

        DirectoryCacheEntry entry = directoryLeaseManager.getCacheEntry(directoryPath);
        entry.updateChild("file1.txt", 1024L, 1000L, false, 0x20, 500L, 800L);
        entry.updateChild("file2.txt", 2048L, 2000L, false, 0x20, 600L, 900L);
        entry.markComplete();

        // Test FILE_ADDED - should invalidate cache
        directoryLeaseManager.handleDirectoryChange(directoryPath, "file3.txt", DirectoryChangeNotifier.DirectoryChangeType.FILE_ADDED);
        assertFalse(entry.isComplete());

        // Re-setup for next test
        entry.updateChild("file1.txt", 1024L, 1000L, false, 0x20, 500L, 800L);
        entry.markComplete();

        // Test FILE_REMOVED
        directoryLeaseManager.handleDirectoryChange(directoryPath, "file1.txt", DirectoryChangeNotifier.DirectoryChangeType.FILE_REMOVED);
        assertFalse(entry.hasChild("file1.txt"));

        // Test FILE_MODIFIED
        entry.updateChild("file2.txt", 2048L, 2000L, false, 0x20, 600L, 900L);
        directoryLeaseManager.handleDirectoryChange(directoryPath, "file2.txt", DirectoryChangeNotifier.DirectoryChangeType.FILE_MODIFIED);
        assertFalse(entry.hasChild("file2.txt")); // Should be removed to force refresh

        // Test DIRECTORY_RENAMED - should invalidate entire cache
        entry.updateChild("file3.txt", 3072L, 3000L, false, 0x20, 700L, 1000L);
        entry.markComplete();
        directoryLeaseManager.handleDirectoryChange(directoryPath, "", DirectoryChangeNotifier.DirectoryChangeType.DIRECTORY_RENAMED);
        assertFalse(entry.isComplete());
        assertTrue(entry.getChildren().isEmpty());
    }

    @Test
    public void testHandleDirectoryLeaseBreak() {
        String directoryPath = "/test/dir";
        Smb2LeaseKey leaseKey = new Smb2LeaseKey();

        // Create cache entry
        when(baseLeaseManager.requestLease(anyString(), anyInt())).thenReturn(leaseKey);
        directoryLeaseManager.requestDirectoryLease(directoryPath, DirectoryLeaseState.DIRECTORY_READ_HANDLE,
                DirectoryCacheScope.IMMEDIATE_CHILDREN);

        DirectoryCacheEntry entry = directoryLeaseManager.getCacheEntry(directoryPath);
        entry.updateChild("file1.txt", 1024L, 1000L, false, 0x20, 500L, 800L);
        entry.markComplete();

        // Break lease with loss of read cache
        int newState = Smb2LeaseState.SMB2_LEASE_HANDLE_CACHING; // Lost read cache
        directoryLeaseManager.handleDirectoryLeaseBreak(leaseKey, newState);

        // Cache should be invalidated
        assertFalse(entry.isComplete());

        // Verify base lease manager was called
        verify(baseLeaseManager).handleLeaseBreak(leaseKey, newState);
    }

    @Test
    public void testReleaseDirectoryLease() {
        String directoryPath = "/test/dir";
        Smb2LeaseKey leaseKey = new Smb2LeaseKey();

        // Create cache entry
        when(baseLeaseManager.requestLease(anyString(), anyInt())).thenReturn(leaseKey);
        directoryLeaseManager.requestDirectoryLease(directoryPath, DirectoryLeaseState.DIRECTORY_READ_HANDLE,
                DirectoryCacheScope.IMMEDIATE_CHILDREN);

        // Verify entry exists
        assertNotNull(directoryLeaseManager.getCacheEntry(directoryPath));

        // Release lease
        directoryLeaseManager.releaseDirectoryLease(directoryPath);

        // Entry should be removed
        assertNull(directoryLeaseManager.getCacheEntry(directoryPath));

        // Verify base lease manager was called
        verify(baseLeaseManager).releaseLease(leaseKey);
    }

    @Test
    public void testShutdown() {
        String directoryPath = "/test/dir";
        Smb2LeaseKey leaseKey = new Smb2LeaseKey();

        // Create cache entry
        when(baseLeaseManager.requestLease(anyString(), anyInt())).thenReturn(leaseKey);
        directoryLeaseManager.requestDirectoryLease(directoryPath, DirectoryLeaseState.DIRECTORY_READ_HANDLE,
                DirectoryCacheScope.IMMEDIATE_CHILDREN);

        // Shutdown
        directoryLeaseManager.shutdown();

        // Verify cleanup
        assertNull(directoryLeaseManager.getCacheEntry(directoryPath));
    }

    @Test
    public void testMultipleDirectories() {
        String dir1 = "/test/dir1";
        String dir2 = "/test/dir2";
        String dir3 = "/test/dir3";

        Smb2LeaseKey key1 = new Smb2LeaseKey();
        Smb2LeaseKey key2 = new Smb2LeaseKey();
        Smb2LeaseKey key3 = new Smb2LeaseKey();

        when(baseLeaseManager.requestLease(dir1, DirectoryLeaseState.DIRECTORY_READ_HANDLE)).thenReturn(key1);
        when(baseLeaseManager.requestLease(dir2, DirectoryLeaseState.DIRECTORY_READ_HANDLE)).thenReturn(key2);
        when(baseLeaseManager.requestLease(dir3, DirectoryLeaseState.DIRECTORY_FULL)).thenReturn(key3);

        // Request leases for multiple directories
        directoryLeaseManager.requestDirectoryLease(dir1, DirectoryLeaseState.DIRECTORY_READ_HANDLE,
                DirectoryCacheScope.IMMEDIATE_CHILDREN);
        directoryLeaseManager.requestDirectoryLease(dir2, DirectoryLeaseState.DIRECTORY_READ_HANDLE, DirectoryCacheScope.METADATA_ONLY);
        directoryLeaseManager.requestDirectoryLease(dir3, DirectoryLeaseState.DIRECTORY_FULL, DirectoryCacheScope.RECURSIVE_TREE);

        // Verify all cache entries exist
        assertNotNull(directoryLeaseManager.getCacheEntry(dir1));
        assertNotNull(directoryLeaseManager.getCacheEntry(dir2));
        assertNotNull(directoryLeaseManager.getCacheEntry(dir3));

        // Verify different scopes
        assertEquals(DirectoryCacheScope.IMMEDIATE_CHILDREN, directoryLeaseManager.getCacheEntry(dir1).getScope());
        assertEquals(DirectoryCacheScope.METADATA_ONLY, directoryLeaseManager.getCacheEntry(dir2).getScope());
        assertEquals(DirectoryCacheScope.RECURSIVE_TREE, directoryLeaseManager.getCacheEntry(dir3).getScope());
    }
}