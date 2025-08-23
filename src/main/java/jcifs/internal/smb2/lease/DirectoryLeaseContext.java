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

import jcifs.internal.smb2.create.CreateContextRequest;
import jcifs.internal.util.SMBUtil;

/**
 * Directory Lease Context for SMB3 directory leasing
 *
 * This context extends standard lease context with directory-specific metadata
 * for enhanced directory caching capabilities.
 */
public class DirectoryLeaseContext implements CreateContextRequest {

    /**
     * Context name for directory lease request
     */
    public static final String NAME_DIRECTORY_REQUEST = "DLse";

    /**
     * Context name for directory lease response
     */
    public static final String NAME_DIRECTORY_RESPONSE = "DLse";

    private static final byte[] CONTEXT_NAME_BYTES = NAME_DIRECTORY_REQUEST.getBytes();

    /**
     * Directory lease flag for recursive caching
     */
    public static final int DIRECTORY_LEASE_FLAG_RECURSIVE = 0x00000001;

    /**
     * Directory lease flag for enabling notifications
     */
    public static final int DIRECTORY_LEASE_FLAG_NOTIFICATIONS = 0x00000002;

    private Smb2LeaseKey leaseKey;
    private int leaseState;
    private DirectoryCacheScope cacheScope;
    private long maxCacheAge;
    private boolean notificationEnabled;
    private int notificationFilter;

    /**
     * Create a new directory lease context
     *
     * @param key the lease key
     * @param leaseState requested lease state
     * @param scope cache scope for directory entries
     */
    public DirectoryLeaseContext(Smb2LeaseKey key, int leaseState, DirectoryCacheScope scope) {
        this.leaseKey = key;
        this.leaseState = leaseState;
        this.cacheScope = scope;
        this.maxCacheAge = 30000; // 30 seconds default
        this.notificationEnabled = true;
        this.notificationFilter = 0;
    }

    @Override
    public byte[] getName() {
        return CONTEXT_NAME_BYTES;
    }

    /**
     * @return the lease key
     */
    public Smb2LeaseKey getLeaseKey() {
        return leaseKey;
    }

    /**
     * @param leaseKey the lease key to set
     */
    public void setLeaseKey(Smb2LeaseKey leaseKey) {
        this.leaseKey = leaseKey;
    }

    /**
     * @return the lease state
     */
    public int getLeaseState() {
        return leaseState;
    }

    /**
     * @param leaseState the lease state to set
     */
    public void setLeaseState(int leaseState) {
        this.leaseState = leaseState;
    }

    /**
     * @return the cache scope
     */
    public DirectoryCacheScope getCacheScope() {
        return cacheScope;
    }

    /**
     * @param cacheScope the cache scope to set
     */
    public void setCacheScope(DirectoryCacheScope cacheScope) {
        this.cacheScope = cacheScope;
    }

    /**
     * @return the maximum cache age in milliseconds
     */
    public long getMaxCacheAge() {
        return maxCacheAge;
    }

    /**
     * @param maxCacheAge the maximum cache age in milliseconds
     */
    public void setMaxCacheAge(long maxCacheAge) {
        this.maxCacheAge = maxCacheAge;
    }

    /**
     * @return true if change notifications are enabled
     */
    public boolean isNotificationEnabled() {
        return notificationEnabled;
    }

    /**
     * @param notificationEnabled true to enable change notifications
     */
    public void setNotificationEnabled(boolean notificationEnabled) {
        this.notificationEnabled = notificationEnabled;
    }

    /**
     * @return the notification filter flags
     */
    public int getNotificationFilter() {
        return notificationFilter;
    }

    /**
     * @param notificationFilter the notification filter flags
     */
    public void setNotificationFilter(int notificationFilter) {
        this.notificationFilter = notificationFilter;
    }

    /**
     * Get the standard lease size for encoding/decoding
     * @return the standard lease context size
     */
    protected int getStandardLeaseSize() {
        // Standard lease V2 size: LeaseKey(16) + LeaseState(4) + Flags(4) + reserved fields
        return 32;
    }

    @Override
    public int size() {
        // Context header: 16 bytes
        // Name: 4 bytes ("DLse")
        // Padding: 4 bytes (to align data to 8-byte boundary)
        // Standard lease data: 32 bytes
        // Directory-specific data: 20 bytes (CacheScope(4) + MaxCacheAge(8) + Flags(4) + NotificationFilter(4))
        return 16 + 4 + 4 + 32 + 20;
    }

    @Override
    public int encode(byte[] buffer, int offset) {
        int start = offset;

        // Write context header
        SMBUtil.writeInt4(0, buffer, offset); // Next (offset to next context, 0 for last)
        offset += 4;

        SMBUtil.writeInt2(16, buffer, offset); // NameOffset (from start of context)
        offset += 2;

        SMBUtil.writeInt2(4, buffer, offset); // NameLength
        offset += 2;

        SMBUtil.writeInt2(0, buffer, offset); // Reserved
        offset += 2;

        SMBUtil.writeInt2(24, buffer, offset); // DataOffset (from start of context)
        offset += 2;

        SMBUtil.writeInt4(52, buffer, offset); // DataLength (32 standard + 20 directory-specific)
        offset += 4;

        // Write context name
        System.arraycopy(CONTEXT_NAME_BYTES, 0, buffer, offset, 4);
        offset += 4;

        // Padding to align data to 8-byte boundary
        offset += 4;

        // Write standard lease data (32 bytes)
        leaseKey.encode(buffer, offset); // LeaseKey (16 bytes)
        offset += 16;

        SMBUtil.writeInt4(leaseState, buffer, offset); // LeaseState (4 bytes)
        offset += 4;

        SMBUtil.writeInt4(0, buffer, offset); // LeaseFlags (4 bytes) - standard lease flags
        offset += 4;

        SMBUtil.writeInt8(0, buffer, offset); // LeaseDuration (8 bytes) - reserved
        offset += 8;

        // Write directory-specific data (20 bytes)

        // CacheScope (4 bytes)
        SMBUtil.writeInt4(cacheScope.ordinal(), buffer, offset);
        offset += 4;

        // MaxCacheAge (8 bytes)
        SMBUtil.writeInt8(maxCacheAge, buffer, offset);
        offset += 8;

        // Directory flags (4 bytes)
        int flags = 0;
        if (cacheScope == DirectoryCacheScope.RECURSIVE_TREE) {
            flags |= DIRECTORY_LEASE_FLAG_RECURSIVE;
        }
        if (notificationEnabled) {
            flags |= DIRECTORY_LEASE_FLAG_NOTIFICATIONS;
        }
        SMBUtil.writeInt4(flags, buffer, offset);
        offset += 4;

        // NotificationFilter (4 bytes)
        SMBUtil.writeInt4(notificationFilter, buffer, offset);
        offset += 4;

        return offset - start;
    }

    /**
     * Decode directory lease context from buffer
     *
     * @param buffer the buffer containing the context data
     * @param offset offset in the buffer
     * @param length length of the context data
     */
    public void decode(byte[] buffer, int offset, int length) {
        // Skip context header (16 bytes) and name (4 bytes) and padding (4 bytes)
        int dataOffset = offset + 24;

        // Decode standard lease data
        byte[] keyBytes = new byte[16];
        System.arraycopy(buffer, dataOffset, keyBytes, 0, 16);
        this.leaseKey = new Smb2LeaseKey(keyBytes);
        dataOffset += 16;

        this.leaseState = SMBUtil.readInt4(buffer, dataOffset);
        dataOffset += 4;

        // Skip standard lease flags (4 bytes)
        dataOffset += 4;

        // Skip lease duration (8 bytes)
        dataOffset += 8;

        // Decode directory-specific data if present
        if (length > 24 + getStandardLeaseSize()) {
            int scopeOrdinal = SMBUtil.readInt4(buffer, dataOffset);
            this.cacheScope = DirectoryCacheScope.values()[scopeOrdinal];
            dataOffset += 4;

            this.maxCacheAge = SMBUtil.readInt8(buffer, dataOffset);
            dataOffset += 8;

            int flags = SMBUtil.readInt4(buffer, dataOffset);
            this.notificationEnabled = (flags & DIRECTORY_LEASE_FLAG_NOTIFICATIONS) != 0;
            dataOffset += 4;

            this.notificationFilter = SMBUtil.readInt4(buffer, dataOffset);
        }
    }
}