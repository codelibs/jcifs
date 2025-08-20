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

/**
 * SMB2 Lease State constants
 *
 * MS-SMB2 2.2.13.2.8
 */
public class Smb2LeaseState {

    /**
     * No lease caching
     */
    public static final int SMB2_LEASE_NONE = 0x00;

    /**
     * Read caching lease (R)
     */
    public static final int SMB2_LEASE_READ_CACHING = 0x01;

    /**
     * Handle caching lease (H)
     */
    public static final int SMB2_LEASE_HANDLE_CACHING = 0x02;

    /**
     * Write caching lease (W)
     */
    public static final int SMB2_LEASE_WRITE_CACHING = 0x04;

    /**
     * Read and Handle caching (RH)
     */
    public static final int SMB2_LEASE_READ_HANDLE = 0x03;

    /**
     * Read and Write caching (RW)
     */
    public static final int SMB2_LEASE_READ_WRITE = 0x05;

    /**
     * Full caching - Read, Write and Handle (RWH)
     */
    public static final int SMB2_LEASE_FULL = 0x07;

    private Smb2LeaseState() {
        // Utility class
    }

    /**
     * Check if state has read caching
     * @param state lease state
     * @return true if read caching is enabled
     */
    public static boolean hasReadCaching(int state) {
        return (state & SMB2_LEASE_READ_CACHING) != 0;
    }

    /**
     * Check if state has handle caching
     * @param state lease state
     * @return true if handle caching is enabled
     */
    public static boolean hasHandleCaching(int state) {
        return (state & SMB2_LEASE_HANDLE_CACHING) != 0;
    }

    /**
     * Check if state has write caching
     * @param state lease state
     * @return true if write caching is enabled
     */
    public static boolean hasWriteCaching(int state) {
        return (state & SMB2_LEASE_WRITE_CACHING) != 0;
    }
}