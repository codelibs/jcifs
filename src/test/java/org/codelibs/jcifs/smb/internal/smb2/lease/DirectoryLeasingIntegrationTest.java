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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.List;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.SmbFile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Integration tests for directory leasing functionality
 */
public class DirectoryLeasingIntegrationTest {

    @Mock
    private CIFSContext context;

    @Mock
    private Configuration config;

    @Mock
    private SmbFile mockFile1;

    @Mock
    private SmbFile mockFile2;

    private LeaseManager baseLeaseManager;
    private DirectoryLeaseManager directoryLeaseManager;
    private AutoCloseable mocks;

    @BeforeEach
    public void setUp() throws Exception {
        mocks = MockitoAnnotations.openMocks(this);

        when(context.getConfig()).thenReturn(config);
        when(config.isDirectoryNotificationsEnabled()).thenReturn(false);

        // Create real lease manager for integration testing
        baseLeaseManager = new LeaseManager(context);
        directoryLeaseManager = new DirectoryLeaseManager(context, baseLeaseManager);
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (directoryLeaseManager != null) {
            directoryLeaseManager.shutdown();
        }
        if (baseLeaseManager != null) {
            baseLeaseManager.shutdown();
        }
        if (mocks != null) {
            mocks.close();
        }
    }

    @Test
    public void testCompleteDirectoryLeasingWorkflow() throws Exception {
        String directoryPath = "/test/integration";

        // Setup mock files
        when(mockFile1.getName()).thenReturn("document.txt");
        when(mockFile1.length()).thenReturn(2048L);
        when(mockFile1.lastModified()).thenReturn(System.currentTimeMillis() - 3600000);
        when(mockFile1.isDirectory()).thenReturn(false);
        when(mockFile1.getAttributes()).thenReturn(0x20); // FILE_ATTRIBUTE_ARCHIVE
        when(mockFile1.createTime()).thenReturn(System.currentTimeMillis() - 7200000);
        when(mockFile1.lastAccess()).thenReturn(System.currentTimeMillis() - 1800000);

        when(mockFile2.getName()).thenReturn("subfolder");
        when(mockFile2.length()).thenReturn(0L);
        when(mockFile2.lastModified()).thenReturn(System.currentTimeMillis() - 1800000);
        when(mockFile2.isDirectory()).thenReturn(true);
        when(mockFile2.getAttributes()).thenReturn(0x10); // FILE_ATTRIBUTE_DIRECTORY
        when(mockFile2.createTime()).thenReturn(System.currentTimeMillis() - 7200000);
        when(mockFile2.lastAccess()).thenReturn(System.currentTimeMillis() - 900000);

        // Step 1: Request directory lease
        Smb2LeaseKey leaseKey = directoryLeaseManager.requestDirectoryLease(directoryPath, DirectoryLeaseState.DIRECTORY_READ_HANDLE,
                DirectoryCacheScope.IMMEDIATE_CHILDREN);

        assertNotNull(leaseKey);

        // Step 2: Verify cache entry was created
        DirectoryCacheEntry cacheEntry = directoryLeaseManager.getCacheEntry(directoryPath);
        assertNotNull(cacheEntry);
        assertEquals(directoryPath, cacheEntry.getDirectoryPath());
        assertEquals(DirectoryCacheScope.IMMEDIATE_CHILDREN, cacheEntry.getScope());
        assertFalse(cacheEntry.isComplete());

        // Step 3: Verify can cache directory listing
        assertTrue(directoryLeaseManager.canCacheDirectoryListing(directoryPath));

        // Step 4: Initially no cached listing
        assertNull(directoryLeaseManager.getCachedDirectoryListing(directoryPath));

        // Step 5: Simulate directory enumeration and update cache
        List<SmbFile> files = Arrays.asList(mockFile1, mockFile2);
        directoryLeaseManager.updateDirectoryCache(directoryPath, files);

        // Step 6: Verify cache is complete and populated
        assertTrue(cacheEntry.isComplete());
        assertEquals(2, cacheEntry.getChildren().size());
        assertTrue(cacheEntry.hasChild("document.txt"));
        assertTrue(cacheEntry.hasChild("subfolder"));

        // Step 7: Verify cached directory listing
        DirectoryCacheEntry verifyCacheEntry = directoryLeaseManager.getCacheEntry(directoryPath);
        assertNotNull(verifyCacheEntry);
        assertTrue(verifyCacheEntry.isComplete());
        assertEquals(2, verifyCacheEntry.getChildren().size());

        // Step 8: Test change notifications
        // Simulate file addition
        directoryLeaseManager.handleDirectoryChange(directoryPath, "newfile.txt", DirectoryChangeNotifier.DirectoryChangeType.FILE_ADDED);

        // Cache should be invalidated
        assertFalse(cacheEntry.isComplete());

        // Step 9: Test lease break
        // Re-populate cache
        directoryLeaseManager.updateDirectoryCache(directoryPath, files);
        assertTrue(cacheEntry.isComplete());

        // Simulate lease break with loss of read cache
        directoryLeaseManager.handleDirectoryLeaseBreak(leaseKey, Smb2LeaseState.SMB2_LEASE_HANDLE_CACHING);

        // Cache should be invalidated
        assertFalse(cacheEntry.isComplete());

        // Step 10: Test lease release
        directoryLeaseManager.releaseDirectoryLease(directoryPath);

        // Cache entry should be removed
        assertNull(directoryLeaseManager.getCacheEntry(directoryPath));
        assertFalse(directoryLeaseManager.canCacheDirectoryListing(directoryPath));
    }

    @Test
    public void testMultipleDirectoryCaching() throws Exception {
        String dir1 = "/test/dir1";
        String dir2 = "/test/dir2";

        // Setup mock files for this test
        when(mockFile1.getName()).thenReturn("document.txt");
        when(mockFile1.length()).thenReturn(2048L);
        when(mockFile1.lastModified()).thenReturn(System.currentTimeMillis() - 3600000);
        when(mockFile1.isDirectory()).thenReturn(false);
        when(mockFile1.getAttributes()).thenReturn(0x20);
        when(mockFile1.createTime()).thenReturn(System.currentTimeMillis() - 7200000);
        when(mockFile1.lastAccess()).thenReturn(System.currentTimeMillis() - 1800000);

        when(mockFile2.getName()).thenReturn("subfolder");
        when(mockFile2.length()).thenReturn(0L);
        when(mockFile2.lastModified()).thenReturn(System.currentTimeMillis() - 1800000);
        when(mockFile2.isDirectory()).thenReturn(true);
        when(mockFile2.getAttributes()).thenReturn(0x10);
        when(mockFile2.createTime()).thenReturn(System.currentTimeMillis() - 7200000);
        when(mockFile2.lastAccess()).thenReturn(System.currentTimeMillis() - 900000);

        // Request leases for both directories
        Smb2LeaseKey key1 = directoryLeaseManager.requestDirectoryLease(dir1, DirectoryLeaseState.DIRECTORY_READ_HANDLE,
                DirectoryCacheScope.IMMEDIATE_CHILDREN);

        Smb2LeaseKey key2 =
                directoryLeaseManager.requestDirectoryLease(dir2, DirectoryLeaseState.DIRECTORY_FULL, DirectoryCacheScope.RECURSIVE_TREE);

        assertNotNull(key1);
        assertNotNull(key2);
        assertNotEquals(key1, key2);

        // Verify both cache entries exist
        DirectoryCacheEntry entry1 = directoryLeaseManager.getCacheEntry(dir1);
        DirectoryCacheEntry entry2 = directoryLeaseManager.getCacheEntry(dir2);

        assertNotNull(entry1);
        assertNotNull(entry2);
        assertEquals(DirectoryCacheScope.IMMEDIATE_CHILDREN, entry1.getScope());
        assertEquals(DirectoryCacheScope.RECURSIVE_TREE, entry2.getScope());

        // Update first directory cache
        List<SmbFile> files1 = Arrays.asList(mockFile1);
        directoryLeaseManager.updateDirectoryCache(dir1, files1);

        // Update second directory cache
        List<SmbFile> files2 = Arrays.asList(mockFile2);
        directoryLeaseManager.updateDirectoryCache(dir2, files2);

        // Verify both caches are independent
        assertTrue(entry1.isComplete());
        assertTrue(entry2.isComplete());
        assertTrue(entry1.hasChild("document.txt"));
        assertFalse(entry1.hasChild("subfolder"));
        assertTrue(entry2.hasChild("subfolder"));
        assertFalse(entry2.hasChild("document.txt"));

        // Test individual change notification
        directoryLeaseManager.handleDirectoryChange(dir1, "document.txt", DirectoryChangeNotifier.DirectoryChangeType.FILE_REMOVED);

        // Only first directory should be affected
        assertFalse(entry1.hasChild("document.txt"));
        assertTrue(entry2.hasChild("subfolder"));

        // Test individual lease break
        directoryLeaseManager.handleDirectoryLeaseBreak(key2, Smb2LeaseState.SMB2_LEASE_NONE);

        // Only second directory should be invalidated
        assertFalse(entry2.isComplete());
        // First directory should still be cached (though modified by previous change)
        assertNotNull(directoryLeaseManager.getCacheEntry(dir1));
    }

    @Test
    public void testCacheExpiration() throws Exception {
        String directoryPath = "/test/expiration";

        // Request lease and update cache
        directoryLeaseManager.requestDirectoryLease(directoryPath, DirectoryLeaseState.DIRECTORY_READ_HANDLE,
                DirectoryCacheScope.IMMEDIATE_CHILDREN);

        DirectoryCacheEntry entry = directoryLeaseManager.getCacheEntry(directoryPath);
        assertNotNull(entry);

        // Set very short expiration time
        entry.setMaxAge(50); // 50ms

        // Update cache
        List<SmbFile> files = Arrays.asList(mockFile1);
        directoryLeaseManager.updateDirectoryCache(directoryPath, files);

        assertTrue(entry.isComplete());
        assertFalse(entry.needsRefresh());

        // Wait for expiration
        Thread.sleep(100);

        assertTrue(entry.isExpired());
        assertTrue(entry.needsRefresh());

        // After expiration, cache should be treated as invalid by manager
        // (In real implementation, expired entries might be cleaned up automatically)
    }

    @Test
    public void testDirectoryLeaseContextIntegration() {
        Smb2LeaseKey key = new Smb2LeaseKey();
        DirectoryLeaseContext context =
                new DirectoryLeaseContext(key, DirectoryLeaseState.DIRECTORY_FULL, DirectoryCacheScope.RECURSIVE_TREE);

        context.setMaxCacheAge(60000L);
        context.setNotificationEnabled(true);
        context.setNotificationFilter(0x1F);

        // Test encoding and decoding roundtrip
        byte[] buffer = new byte[context.size()];
        int encoded = context.encode(buffer, 0);
        assertEquals(context.size(), encoded);

        DirectoryLeaseContext decodedContext = new DirectoryLeaseContext(new Smb2LeaseKey(), 0, DirectoryCacheScope.IMMEDIATE_CHILDREN);

        decodedContext.decode(buffer, 0, buffer.length);

        // Verify roundtrip integrity
        assertEquals(context.getLeaseState(), decodedContext.getLeaseState());
        assertEquals(context.getCacheScope(), decodedContext.getCacheScope());
        assertEquals(context.getMaxCacheAge(), decodedContext.getMaxCacheAge());
        assertEquals(context.isNotificationEnabled(), decodedContext.isNotificationEnabled());
        assertEquals(context.getNotificationFilter(), decodedContext.getNotificationFilter());
        assertArrayEquals(context.getLeaseKey().getKey(), decodedContext.getLeaseKey().getKey());
    }

    @Test
    public void testConcurrentAccess() throws Exception {
        String directoryPath = "/test/concurrent";

        directoryLeaseManager.requestDirectoryLease(directoryPath, DirectoryLeaseState.DIRECTORY_READ_HANDLE,
                DirectoryCacheScope.IMMEDIATE_CHILDREN);

        DirectoryCacheEntry entry = directoryLeaseManager.getCacheEntry(directoryPath);

        // Test concurrent updates
        Thread[] updateThreads = new Thread[5];
        for (int i = 0; i < updateThreads.length; i++) {
            final int threadId = i;
            updateThreads[i] = new Thread(() -> {
                for (int j = 0; j < 20; j++) {
                    String fileName = "thread" + threadId + "_file" + j + ".txt";
                    entry.updateChild(fileName, j * 100L, System.currentTimeMillis(), false, 0x20, System.currentTimeMillis() - 10000,
                            System.currentTimeMillis() - 5000);
                }
            });
            updateThreads[i].start();
        }

        // Test concurrent reads
        Thread[] readThreads = new Thread[3];
        for (int i = 0; i < readThreads.length; i++) {
            readThreads[i] = new Thread(() -> {
                for (int j = 0; j < 100; j++) {
                    List<DirectoryCacheEntry.FileInfo> children = entry.getChildren();
                    // Just read, don't assert specific counts due to race conditions
                    assertNotNull(children);
                }
            });
            readThreads[i].start();
        }

        // Wait for all threads
        for (Thread thread : updateThreads) {
            thread.join(5000);
        }
        for (Thread thread : readThreads) {
            thread.join(5000);
        }

        // Verify final state
        assertEquals(100, entry.getChildren().size());
        assertTrue(entry.hasChanges());
    }
}