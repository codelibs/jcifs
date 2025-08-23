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
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for DirectoryLeaseState
 */
public class DirectoryLeaseStateTest {

    @Test
    public void testDirectoryLeaseConstants() {
        // Test that directory lease states use correct base values
        assertEquals(Smb2LeaseState.SMB2_LEASE_READ_CACHING | Smb2LeaseState.SMB2_LEASE_HANDLE_CACHING,
                DirectoryLeaseState.DIRECTORY_READ_HANDLE);

        assertEquals(Smb2LeaseState.SMB2_LEASE_FULL, DirectoryLeaseState.DIRECTORY_FULL);
    }

    @Test
    public void testCanCacheEnumeration() {
        // Should return true when read caching is enabled
        assertTrue(DirectoryLeaseState.canCacheEnumeration(Smb2LeaseState.SMB2_LEASE_READ_CACHING));
        assertTrue(DirectoryLeaseState.canCacheEnumeration(DirectoryLeaseState.DIRECTORY_READ_HANDLE));
        assertTrue(DirectoryLeaseState.canCacheEnumeration(DirectoryLeaseState.DIRECTORY_FULL));

        // Should return false when read caching is not enabled
        assertFalse(DirectoryLeaseState.canCacheEnumeration(Smb2LeaseState.SMB2_LEASE_NONE));
        assertFalse(DirectoryLeaseState.canCacheEnumeration(Smb2LeaseState.SMB2_LEASE_HANDLE_CACHING));
        assertFalse(DirectoryLeaseState.canCacheEnumeration(Smb2LeaseState.SMB2_LEASE_WRITE_CACHING));
    }

    @Test
    public void testCanKeepHandlesOpen() {
        // Should return true when handle caching is enabled
        assertTrue(DirectoryLeaseState.canKeepHandlesOpen(Smb2LeaseState.SMB2_LEASE_HANDLE_CACHING));
        assertTrue(DirectoryLeaseState.canKeepHandlesOpen(DirectoryLeaseState.DIRECTORY_READ_HANDLE));
        assertTrue(DirectoryLeaseState.canKeepHandlesOpen(DirectoryLeaseState.DIRECTORY_FULL));

        // Should return false when handle caching is not enabled
        assertFalse(DirectoryLeaseState.canKeepHandlesOpen(Smb2LeaseState.SMB2_LEASE_NONE));
        assertFalse(DirectoryLeaseState.canKeepHandlesOpen(Smb2LeaseState.SMB2_LEASE_READ_CACHING));
        assertFalse(DirectoryLeaseState.canKeepHandlesOpen(Smb2LeaseState.SMB2_LEASE_WRITE_CACHING));
    }

    @Test
    public void testCanCacheModifications() {
        // Should return true when write caching is enabled
        assertTrue(DirectoryLeaseState.canCacheModifications(Smb2LeaseState.SMB2_LEASE_WRITE_CACHING));
        assertTrue(DirectoryLeaseState.canCacheModifications(Smb2LeaseState.SMB2_LEASE_READ_WRITE));
        assertTrue(DirectoryLeaseState.canCacheModifications(DirectoryLeaseState.DIRECTORY_FULL));

        // Should return false when write caching is not enabled
        assertFalse(DirectoryLeaseState.canCacheModifications(Smb2LeaseState.SMB2_LEASE_NONE));
        assertFalse(DirectoryLeaseState.canCacheModifications(Smb2LeaseState.SMB2_LEASE_READ_CACHING));
        assertFalse(DirectoryLeaseState.canCacheModifications(Smb2LeaseState.SMB2_LEASE_HANDLE_CACHING));
        assertFalse(DirectoryLeaseState.canCacheModifications(DirectoryLeaseState.DIRECTORY_READ_HANDLE));
    }
}