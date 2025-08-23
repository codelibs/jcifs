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

/**
 * Directory-specific lease state definitions for SMB3 directory leasing
 *
 * Standard lease states apply with directory-specific semantics:
 * - READ_CACHING: Can cache directory enumeration results, file existence queries, and basic file attributes
 * - HANDLE_CACHING: Can keep directory handle open and cache subdirectory handles
 * - WRITE_CACHING: Can cache file creation/deletion notifications and perform optimistic file operations
 */
public class DirectoryLeaseState {

    /**
     * Directory Read and Handle caching (RH) - recommended for directory operations
     */
    public static final int DIRECTORY_READ_HANDLE = Smb2LeaseState.SMB2_LEASE_READ_CACHING | Smb2LeaseState.SMB2_LEASE_HANDLE_CACHING;

    /**
     * Directory Full caching (RWH) - all three lease types
     */
    public static final int DIRECTORY_FULL = Smb2LeaseState.SMB2_LEASE_FULL;

    /**
     * Check if directory can cache enumeration results
     * @param state lease state
     * @return true if directory enumeration can be cached
     */
    public static boolean canCacheEnumeration(int state) {
        return Smb2LeaseState.hasReadCaching(state);
    }

    /**
     * Check if directory can keep handles open
     * @param state lease state
     * @return true if directory handles can be kept open
     */
    public static boolean canKeepHandlesOpen(int state) {
        return Smb2LeaseState.hasHandleCaching(state);
    }

    /**
     * Check if directory can cache modifications
     * @param state lease state
     * @return true if directory modifications can be cached
     */
    public static boolean canCacheModifications(int state) {
        return Smb2LeaseState.hasWriteCaching(state);
    }
}