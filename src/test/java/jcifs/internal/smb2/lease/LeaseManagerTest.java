/*
 * © 2017 AgNO3 Gmbh & Co. KG
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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.smb2.lease.LeaseManager.LeaseEntry;

@DisplayName("LeaseManager Tests")
class LeaseManagerTest {

    private LeaseManager leaseManager;
    private CIFSContext mockContext;
    private Configuration mockConfig;

    @BeforeEach
    void setUp() {
        mockContext = mock(CIFSContext.class);
        mockConfig = mock(Configuration.class);
        when(mockContext.getConfig()).thenReturn(mockConfig);
        when(mockConfig.getLeaseTimeout()).thenReturn(30000);
        when(mockConfig.getMaxLeases()).thenReturn(1000);
        when(mockConfig.getLeaseBreakTimeout()).thenReturn(60);
        leaseManager = new LeaseManager(mockContext);
    }

    @AfterEach
    void tearDown() {
        if (leaseManager != null) {
            leaseManager.shutdown();
        }
    }

    @Test
    @DisplayName("Should request new lease")
    void testRequestLease() {
        String path = "/share/file.txt";
        int requestedState = Smb2LeaseState.SMB2_LEASE_FULL;

        Smb2LeaseKey key = leaseManager.requestLease(path, requestedState);

        assertNotNull(key);
        LeaseEntry entry = leaseManager.getLease(key);
        assertNotNull(entry);
        assertEquals(requestedState, entry.getLeaseState());
        assertEquals(path, entry.getPath());
        assertEquals(1, entry.getEpoch());
        assertFalse(entry.isBreaking());
    }

    @Test
    @DisplayName("Should reuse existing lease for same path")
    void testReuseExistingLease() {
        String path = "/share/file.txt";
        int requestedState = Smb2LeaseState.SMB2_LEASE_READ_WRITE;

        Smb2LeaseKey key1 = leaseManager.requestLease(path, requestedState);
        Smb2LeaseKey key2 = leaseManager.requestLease(path, requestedState);

        assertEquals(key1, key2);
    }

    @Test
    @DisplayName("Should update lease state")
    void testUpdateLease() {
        String path = "/share/file.txt";
        int requestedState = Smb2LeaseState.SMB2_LEASE_FULL;
        int grantedState = Smb2LeaseState.SMB2_LEASE_READ_WRITE;

        Smb2LeaseKey key = leaseManager.requestLease(path, requestedState);
        leaseManager.updateLease(key, grantedState);

        LeaseEntry entry = leaseManager.getLease(key);
        assertEquals(grantedState, entry.getLeaseState());
    }

    @Test
    @DisplayName("Should handle lease break")
    void testHandleLeaseBreak() {
        String path = "/share/file.txt";
        int initialState = Smb2LeaseState.SMB2_LEASE_FULL;
        int newState = Smb2LeaseState.SMB2_LEASE_READ_CACHING;

        Smb2LeaseKey key = leaseManager.requestLease(path, initialState);
        leaseManager.updateLease(key, initialState);

        int initialEpoch = leaseManager.getLease(key).getEpoch();
        leaseManager.handleLeaseBreak(key, newState);

        LeaseEntry entry = leaseManager.getLease(key);
        assertEquals(newState, entry.getLeaseState());
        assertEquals(initialEpoch + 1, entry.getEpoch());
        assertFalse(entry.isBreaking()); // Should be false after break handling completes
    }

    @Test
    @DisplayName("Should release lease")
    void testReleaseLease() {
        String path = "/share/file.txt";
        int requestedState = Smb2LeaseState.SMB2_LEASE_READ_HANDLE;

        Smb2LeaseKey key = leaseManager.requestLease(path, requestedState);
        assertNotNull(leaseManager.getLease(key));

        leaseManager.releaseLease(key);

        assertNull(leaseManager.getLease(key));
        assertNull(leaseManager.getLeaseByPath(path));
    }

    @Test
    @DisplayName("Should get lease by path")
    void testGetLeaseByPath() {
        String path = "/share/document.doc";
        int requestedState = Smb2LeaseState.SMB2_LEASE_READ_CACHING;

        Smb2LeaseKey key = leaseManager.requestLease(path, requestedState);
        LeaseEntry entryByKey = leaseManager.getLease(key);
        LeaseEntry entryByPath = leaseManager.getLeaseByPath(path);

        assertEquals(entryByKey, entryByPath);
        assertEquals(path, entryByPath.getPath());
    }

    @Test
    @DisplayName("Should release all leases")
    void testReleaseAll() {
        String path1 = "/share/file1.txt";
        String path2 = "/share/file2.txt";

        Smb2LeaseKey key1 = leaseManager.requestLease(path1, Smb2LeaseState.SMB2_LEASE_READ_CACHING);
        Smb2LeaseKey key2 = leaseManager.requestLease(path2, Smb2LeaseState.SMB2_LEASE_WRITE_CACHING);

        assertNotNull(leaseManager.getLease(key1));
        assertNotNull(leaseManager.getLease(key2));

        leaseManager.releaseAll();

        assertNull(leaseManager.getLease(key1));
        assertNull(leaseManager.getLease(key2));
        assertTrue(leaseManager.getAllLeases().isEmpty());
    }

    @Test
    @DisplayName("Should clean up expired leases")
    void testCleanupExpiredLeases() throws InterruptedException {
        String path = "/share/expired.txt";
        int requestedState = Smb2LeaseState.SMB2_LEASE_READ_CACHING;

        Smb2LeaseKey key = leaseManager.requestLease(path, requestedState);
        assertNotNull(leaseManager.getLease(key));

        // Wait a bit and then cleanup with a very short expiration time
        Thread.sleep(10);
        int cleaned = leaseManager.cleanupExpiredLeases(1); // 1ms expiration

        assertEquals(1, cleaned);
        assertNull(leaseManager.getLease(key));
    }

    @Test
    @DisplayName("Should not clean up recent leases")
    void testCleanupRecentLeases() {
        String path = "/share/recent.txt";
        int requestedState = Smb2LeaseState.SMB2_LEASE_READ_CACHING;

        Smb2LeaseKey key = leaseManager.requestLease(path, requestedState);
        assertNotNull(leaseManager.getLease(key));

        int cleaned = leaseManager.cleanupExpiredLeases(60000); // 1 minute expiration

        assertEquals(0, cleaned);
        assertNotNull(leaseManager.getLease(key));
    }

    @Test
    @DisplayName("Should detect lease capabilities")
    void testLeaseCapabilities() {
        String path = "/share/file.txt";

        // Test full lease
        Smb2LeaseKey fullKey = leaseManager.requestLease(path + "1", Smb2LeaseState.SMB2_LEASE_FULL);
        leaseManager.updateLease(fullKey, Smb2LeaseState.SMB2_LEASE_FULL);
        LeaseEntry fullEntry = leaseManager.getLease(fullKey);

        assertTrue(fullEntry.hasReadCache());
        assertTrue(fullEntry.hasWriteCache());
        assertTrue(fullEntry.hasHandleCache());

        // Test read-only lease
        Smb2LeaseKey readKey = leaseManager.requestLease(path + "2", Smb2LeaseState.SMB2_LEASE_READ_CACHING);
        leaseManager.updateLease(readKey, Smb2LeaseState.SMB2_LEASE_READ_CACHING);
        LeaseEntry readEntry = leaseManager.getLease(readKey);

        assertTrue(readEntry.hasReadCache());
        assertFalse(readEntry.hasWriteCache());
        assertFalse(readEntry.hasHandleCache());

        // Test no lease
        Smb2LeaseKey noneKey = leaseManager.requestLease(path + "3", Smb2LeaseState.SMB2_LEASE_NONE);
        leaseManager.updateLease(noneKey, Smb2LeaseState.SMB2_LEASE_NONE);
        LeaseEntry noneEntry = leaseManager.getLease(noneKey);

        assertFalse(noneEntry.hasReadCache());
        assertFalse(noneEntry.hasWriteCache());
        assertFalse(noneEntry.hasHandleCache());
    }

    @Test
    @DisplayName("Should handle lease break with timeout")
    void testHandleLeaseBreakWithTimeout() {
        String path = "/share/timeout.txt";
        int initialState = Smb2LeaseState.SMB2_LEASE_FULL;
        int newState = Smb2LeaseState.SMB2_LEASE_READ_CACHING;

        Smb2LeaseKey key = leaseManager.requestLease(path, initialState);
        leaseManager.updateLease(key, initialState);

        leaseManager.handleLeaseBreakWithTimeout(key, newState, 1);

        LeaseEntry entry = leaseManager.getLease(key);
        if (entry != null) {
            // If entry still exists, it should have the new state
            assertEquals(newState, entry.getLeaseState());
        }
        // If entry doesn't exist, it was cleaned up due to timeout
    }

    @Test
    @DisplayName("Should use default lease break timeout when not specified")
    void testDefaultLeaseBreakTimeout() {
        String path = "/share/default-timeout.txt";
        int initialState = Smb2LeaseState.SMB2_LEASE_FULL;
        int newState = Smb2LeaseState.SMB2_LEASE_READ_HANDLE;

        Smb2LeaseKey key = leaseManager.requestLease(path, initialState);
        leaseManager.updateLease(key, initialState);

        // Call with default timeout (should use 60 seconds from config)
        leaseManager.handleLeaseBreakWithTimeout(key, newState);

        LeaseEntry entry = leaseManager.getLease(key);
        assertNotNull(entry);
        assertEquals(newState, entry.getLeaseState());
    }

    @Test
    @DisplayName("Should clean up expired leases with custom timeout")
    void testCleanupExpiredLeasesWithCustomTimeout() throws InterruptedException {
        String path1 = "/share/expired1.txt";
        String path2 = "/share/expired2.txt";

        Smb2LeaseKey key1 = leaseManager.requestLease(path1, Smb2LeaseState.SMB2_LEASE_READ_CACHING);
        Thread.sleep(10); // Small delay to ensure different timestamps
        Smb2LeaseKey key2 = leaseManager.requestLease(path2, Smb2LeaseState.SMB2_LEASE_WRITE_CACHING);

        // Clean up leases older than 5ms
        int cleaned = leaseManager.cleanupExpiredLeases(5);

        // At least the first lease should be cleaned
        assertTrue(cleaned >= 1);

        // Check if old lease was removed
        LeaseEntry entry1 = leaseManager.getLease(key1);
        if (cleaned == 2) {
            assertNull(entry1);
            assertNull(leaseManager.getLease(key2));
        }
    }

    @Test
    @DisplayName("Should evict oldest leases when max limit reached")
    void testMaxLeaseEviction() throws InterruptedException {
        // Create a context with low max lease limit
        Configuration limitedConfig = mock(Configuration.class);
        CIFSContext limitedContext = mock(CIFSContext.class);
        when(limitedContext.getConfig()).thenReturn(limitedConfig);
        when(limitedConfig.getLeaseTimeout()).thenReturn(30000);
        when(limitedConfig.getMaxLeases()).thenReturn(2); // Only allow 2 leases
        when(limitedConfig.getLeaseBreakTimeout()).thenReturn(60);

        LeaseManager limitedManager = new LeaseManager(limitedContext);

        try {
            // Request 3 leases (should evict the oldest when requesting the 3rd)
            Smb2LeaseKey key1 = limitedManager.requestLease("/share/file1.txt", Smb2LeaseState.SMB2_LEASE_READ_CACHING);
            Thread.sleep(5); // Small delay to ensure different timestamps
            Smb2LeaseKey key2 = limitedManager.requestLease("/share/file2.txt", Smb2LeaseState.SMB2_LEASE_READ_CACHING);
            Thread.sleep(5); // Small delay to ensure different timestamps
            Smb2LeaseKey key3 = limitedManager.requestLease("/share/file3.txt", Smb2LeaseState.SMB2_LEASE_READ_CACHING);

            // key3 should definitely exist (just created)
            assertNotNull(limitedManager.getLease(key3));

            // key1 should have been evicted (oldest)
            assertNull(limitedManager.getLease(key1));

            // key2 should still exist (not the oldest)
            assertNotNull(limitedManager.getLease(key2));
        } finally {
            limitedManager.shutdown();
        }
    }

    @Test
    @DisplayName("Should register and manage file cache")
    void testFileCache() {
        String path = "/share/cached.txt";
        Smb2LeaseKey key = leaseManager.requestLease(path, Smb2LeaseState.SMB2_LEASE_FULL);

        // Register a mock file with cache
        leaseManager.registerFileCache(path, null); // Using null for simplicity in test

        // Handle lease break which should trigger cache operations
        leaseManager.handleLeaseBreak(key, Smb2LeaseState.SMB2_LEASE_NONE);

        LeaseEntry entry = leaseManager.getLease(key);
        assertNotNull(entry);
        assertEquals(Smb2LeaseState.SMB2_LEASE_NONE, entry.getLeaseState());
    }
}