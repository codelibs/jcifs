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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import jcifs.CIFSContext;
import jcifs.internal.smb2.lease.LeaseManager.LeaseEntry;

@DisplayName("LeaseManager Tests")
class LeaseManagerTest {

    private LeaseManager leaseManager;
    private CIFSContext mockContext;

    @BeforeEach
    void setUp() {
        mockContext = mock(CIFSContext.class);
        leaseManager = new LeaseManager(mockContext);
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
}