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
 */
package jcifs.internal.smb2.persistent;

import jcifs.internal.smb2.lease.Smb2LeaseKey;
import java.io.Serializable;
import java.util.Arrays;

/**
 * Information about a durable or persistent SMB handle.
 * This class holds all the necessary information to reconnect
 * a handle after network failures or server reboots.
 *
 * @author jcifs team
 */
public class HandleInfo implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String path;
    private final HandleGuid createGuid;
    private final byte[] fileId;
    private final HandleType type;
    private final long timeout;
    private final long createTime;
    private volatile long lastAccessTime;
    private final Smb2LeaseKey leaseKey; // Associated lease if any
    private volatile boolean reconnecting;

    // Not serialized - will be null after deserialization
    private transient Object file; // Reference to SmbFile (avoid circular dependencies)

    /**
     * Create new handle information
     * @param path the file path
     * @param guid the create GUID
     * @param fileId the 16-byte file ID
     * @param type the handle type
     * @param timeout the timeout in milliseconds
     * @param leaseKey the associated lease key (can be null)
     */
    public HandleInfo(String path, HandleGuid guid, byte[] fileId, HandleType type, long timeout, Smb2LeaseKey leaseKey) {
        this.path = path;
        this.createGuid = guid;
        this.fileId = Arrays.copyOf(fileId, 16);
        this.type = type;
        this.timeout = timeout;
        this.createTime = System.currentTimeMillis();
        this.lastAccessTime = createTime;
        this.leaseKey = leaseKey;
        this.reconnecting = false;
    }

    /**
     * Check if this handle has expired
     * @return true if expired
     */
    public boolean isExpired() {
        if (type == HandleType.PERSISTENT) {
            return false; // Persistent handles don't expire
        }
        long elapsed = System.currentTimeMillis() - lastAccessTime;
        return elapsed > timeout;
    }

    /**
     * Update the last access time
     */
    public void updateAccessTime() {
        this.lastAccessTime = System.currentTimeMillis();
    }

    /**
     * Get the file path
     * @return the path
     */
    public String getPath() {
        return path;
    }

    /**
     * Get the create GUID
     * @return the create GUID
     */
    public HandleGuid getCreateGuid() {
        return createGuid;
    }

    /**
     * Get the file ID
     * @return copy of the 16-byte file ID
     */
    public byte[] getFileId() {
        return Arrays.copyOf(fileId, 16);
    }

    /**
     * Get the handle type
     * @return the handle type
     */
    public HandleType getType() {
        return type;
    }

    /**
     * Get the timeout
     * @return the timeout in milliseconds
     */
    public long getTimeout() {
        return timeout;
    }

    /**
     * Get the create time
     * @return the create time
     */
    public long getCreateTime() {
        return createTime;
    }

    /**
     * Get the last access time
     * @return the last access time
     */
    public long getLastAccessTime() {
        return lastAccessTime;
    }

    /**
     * Get the associated lease key
     * @return the lease key (can be null)
     */
    public Smb2LeaseKey getLeaseKey() {
        return leaseKey;
    }

    /**
     * Check if this handle is currently reconnecting
     * @return true if reconnecting
     */
    public boolean isReconnecting() {
        return reconnecting;
    }

    /**
     * Set the reconnecting state
     * @param reconnecting the reconnecting state
     */
    public void setReconnecting(boolean reconnecting) {
        this.reconnecting = reconnecting;
    }

    /**
     * Get the associated file object
     * @return the file object (can be null)
     */
    public Object getFile() {
        return file;
    }

    /**
     * Set the associated file object
     * @param file the file object
     */
    public void setFile(Object file) {
        this.file = file;
    }

    /**
     * Update the file ID after successful create response
     * @param newFileId the new 16-byte file ID
     */
    public void updateFileId(byte[] newFileId) {
        if (newFileId.length != 16) {
            throw new IllegalArgumentException("File ID must be 16 bytes");
        }
        System.arraycopy(newFileId, 0, this.fileId, 0, 16);
    }

    @Override
    public String toString() {
        return "HandleInfo{" + "path='" + path + '\'' + ", createGuid=" + createGuid + ", type=" + type + ", timeout=" + timeout
                + ", reconnecting=" + reconnecting + '}';
    }
}
