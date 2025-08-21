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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Smb2LeaseState Tests")
class Smb2LeaseStateTest {

    @Test
    @DisplayName("Should define correct lease state constants")
    void testLeaseStateConstants() {
        assertEquals(0x00, Smb2LeaseState.SMB2_LEASE_NONE);
        assertEquals(0x01, Smb2LeaseState.SMB2_LEASE_READ_CACHING);
        assertEquals(0x02, Smb2LeaseState.SMB2_LEASE_HANDLE_CACHING);
        assertEquals(0x04, Smb2LeaseState.SMB2_LEASE_WRITE_CACHING);
        assertEquals(0x03, Smb2LeaseState.SMB2_LEASE_READ_HANDLE);
        assertEquals(0x05, Smb2LeaseState.SMB2_LEASE_READ_WRITE);
        assertEquals(0x07, Smb2LeaseState.SMB2_LEASE_FULL);
    }

    @Test
    @DisplayName("Should detect read caching correctly")
    void testHasReadCaching() {
        assertTrue(Smb2LeaseState.hasReadCaching(Smb2LeaseState.SMB2_LEASE_READ_CACHING));
        assertTrue(Smb2LeaseState.hasReadCaching(Smb2LeaseState.SMB2_LEASE_READ_HANDLE));
        assertTrue(Smb2LeaseState.hasReadCaching(Smb2LeaseState.SMB2_LEASE_READ_WRITE));
        assertTrue(Smb2LeaseState.hasReadCaching(Smb2LeaseState.SMB2_LEASE_FULL));

        assertFalse(Smb2LeaseState.hasReadCaching(Smb2LeaseState.SMB2_LEASE_NONE));
        assertFalse(Smb2LeaseState.hasReadCaching(Smb2LeaseState.SMB2_LEASE_HANDLE_CACHING));
        assertFalse(Smb2LeaseState.hasReadCaching(Smb2LeaseState.SMB2_LEASE_WRITE_CACHING));
    }

    @Test
    @DisplayName("Should detect handle caching correctly")
    void testHasHandleCaching() {
        assertTrue(Smb2LeaseState.hasHandleCaching(Smb2LeaseState.SMB2_LEASE_HANDLE_CACHING));
        assertTrue(Smb2LeaseState.hasHandleCaching(Smb2LeaseState.SMB2_LEASE_READ_HANDLE));
        assertTrue(Smb2LeaseState.hasHandleCaching(Smb2LeaseState.SMB2_LEASE_FULL));

        assertFalse(Smb2LeaseState.hasHandleCaching(Smb2LeaseState.SMB2_LEASE_NONE));
        assertFalse(Smb2LeaseState.hasHandleCaching(Smb2LeaseState.SMB2_LEASE_READ_CACHING));
        assertFalse(Smb2LeaseState.hasHandleCaching(Smb2LeaseState.SMB2_LEASE_WRITE_CACHING));
        assertFalse(Smb2LeaseState.hasHandleCaching(Smb2LeaseState.SMB2_LEASE_READ_WRITE));
    }

    @Test
    @DisplayName("Should detect write caching correctly")
    void testHasWriteCaching() {
        assertTrue(Smb2LeaseState.hasWriteCaching(Smb2LeaseState.SMB2_LEASE_WRITE_CACHING));
        assertTrue(Smb2LeaseState.hasWriteCaching(Smb2LeaseState.SMB2_LEASE_READ_WRITE));
        assertTrue(Smb2LeaseState.hasWriteCaching(Smb2LeaseState.SMB2_LEASE_FULL));

        assertFalse(Smb2LeaseState.hasWriteCaching(Smb2LeaseState.SMB2_LEASE_NONE));
        assertFalse(Smb2LeaseState.hasWriteCaching(Smb2LeaseState.SMB2_LEASE_READ_CACHING));
        assertFalse(Smb2LeaseState.hasWriteCaching(Smb2LeaseState.SMB2_LEASE_HANDLE_CACHING));
        assertFalse(Smb2LeaseState.hasWriteCaching(Smb2LeaseState.SMB2_LEASE_READ_HANDLE));
    }

    @Test
    @DisplayName("Should combine lease states correctly")
    void testLeaseStateCombinations() {
        int readAndWrite = Smb2LeaseState.SMB2_LEASE_READ_CACHING | Smb2LeaseState.SMB2_LEASE_WRITE_CACHING;
        assertEquals(Smb2LeaseState.SMB2_LEASE_READ_WRITE, readAndWrite);

        int readAndHandle = Smb2LeaseState.SMB2_LEASE_READ_CACHING | Smb2LeaseState.SMB2_LEASE_HANDLE_CACHING;
        assertEquals(Smb2LeaseState.SMB2_LEASE_READ_HANDLE, readAndHandle);

        int fullLease =
                Smb2LeaseState.SMB2_LEASE_READ_CACHING | Smb2LeaseState.SMB2_LEASE_WRITE_CACHING | Smb2LeaseState.SMB2_LEASE_HANDLE_CACHING;
        assertEquals(Smb2LeaseState.SMB2_LEASE_FULL, fullLease);
    }

    @Test
    @DisplayName("Should handle custom state combinations")
    void testCustomStateCombinations() {
        int customState = 0x06; // Write + Handle but no Read

        assertFalse(Smb2LeaseState.hasReadCaching(customState));
        assertTrue(Smb2LeaseState.hasWriteCaching(customState));
        assertTrue(Smb2LeaseState.hasHandleCaching(customState));
    }

    @Test
    @DisplayName("Should handle zero state")
    void testZeroState() {
        assertFalse(Smb2LeaseState.hasReadCaching(0));
        assertFalse(Smb2LeaseState.hasWriteCaching(0));
        assertFalse(Smb2LeaseState.hasHandleCaching(0));
    }
}
