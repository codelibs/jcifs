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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Cache entry for directory contents with thread-safe operations
 */
public class DirectoryCacheEntry {

    private final String directoryPath;
    private final Smb2LeaseKey leaseKey;
    private final long createTime;
    private volatile long lastUpdateTime;
    private volatile long lastAccessTime;

    private final ConcurrentHashMap<String, FileInfo> children;
    private final ReadWriteLock lock;

    private volatile boolean isComplete;
    private volatile boolean hasChanges;
    private DirectoryCacheScope scope;
    private long maxAge;

    private final AtomicInteger inconsistencyCount = new AtomicInteger(0);

    /**
     * Create a new directory cache entry
     *
     * @param path the directory path
     * @param key the lease key
     * @param scope the cache scope
     */
    public DirectoryCacheEntry(String path, Smb2LeaseKey key, DirectoryCacheScope scope) {
        this.directoryPath = path;
        this.leaseKey = key;
        this.scope = scope;
        this.createTime = System.currentTimeMillis();
        this.lastUpdateTime = createTime;
        this.lastAccessTime = createTime;
        this.maxAge = 30000; // 30 seconds default

        this.children = new ConcurrentHashMap<>();
        this.lock = new ReentrantReadWriteLock();
        this.isComplete = false;
        this.hasChanges = false;
    }

    /**
     * File information cached for a directory entry
     */
    public static class FileInfo {
        private final String name;
        private final long size;
        private final long lastModified;
        private final boolean isDirectory;
        private final long attributes;
        private final long creationTime;
        private final long lastAccessTime;

        /**
         * Create file info from name and attributes
         *
         * @param name file name
         * @param size file size
         * @param lastModified last modified time
         * @param isDirectory true if directory
         * @param attributes file attributes
         * @param creationTime creation time
         * @param lastAccessTime last access time
         */
        public FileInfo(String name, long size, long lastModified, boolean isDirectory, long attributes, long creationTime,
                long lastAccessTime) {
            this.name = name;
            this.size = size;
            this.lastModified = lastModified;
            this.isDirectory = isDirectory;
            this.attributes = attributes;
            this.creationTime = creationTime;
            this.lastAccessTime = lastAccessTime;
        }

        /**
         * Check if this file info matches the given attributes
         *
         * @param otherSize size to compare
         * @param otherLastModified last modified time to compare
         * @param otherAttributes attributes to compare
         * @return true if attributes match
         */
        public boolean matches(long otherSize, long otherLastModified, long otherAttributes) {
            return size == otherSize && lastModified == otherLastModified && attributes == otherAttributes;
        }

        /**
         * Gets the name of this cached file or directory
         * @return the file name
         */
        public String getName() {
            return name;
        }

        /**
         * Gets the size of this cached file in bytes
         * @return the file size
         */
        public long getSize() {
            return size;
        }

        /**
         * Gets the last modification timestamp of this cached item
         * @return the last modified time
         */
        public long getLastModified() {
            return lastModified;
        }

        /**
         * Checks if this cached item represents a directory
         * @return true if this is a directory
         */
        public boolean isDirectory() {
            return isDirectory;
        }

        /**
         * Gets the SMB file attributes for this cached item
         * @return the file attributes
         */
        public long getAttributes() {
            return attributes;
        }

        /**
         * Gets the creation timestamp of this cached item
         * @return the creation time
         */
        public long getCreationTime() {
            return creationTime;
        }

        /**
         * Gets the last access timestamp of this cached item
         * @return the last access time
         */
        public long getLastAccessTime() {
            return lastAccessTime;
        }
    }

    /**
     * Update or add a child entry
     *
     * @param childName child file name
     * @param size file size
     * @param lastModified last modified time
     * @param isDirectory true if directory
     * @param attributes file attributes
     * @param creationTime creation time
     * @param lastAccessTime last access time
     */
    public void updateChild(String childName, long size, long lastModified, boolean isDirectory, long attributes, long creationTime,
            long lastAccessTime) {
        lock.writeLock().lock();
        try {
            FileInfo existing = children.get(childName);
            FileInfo newInfo = new FileInfo(childName, size, lastModified, isDirectory, attributes, creationTime, lastAccessTime);

            if (existing == null || !existing.matches(size, lastModified, attributes)) {
                children.put(childName, newInfo);
                hasChanges = true;
                lastUpdateTime = System.currentTimeMillis();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Remove a child entry
     *
     * @param childName child file name
     */
    public void removeChild(String childName) {
        lock.writeLock().lock();
        try {
            if (children.remove(childName) != null) {
                hasChanges = true;
                lastUpdateTime = System.currentTimeMillis();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Get all children
     *
     * @return list of child file info
     */
    public List<FileInfo> getChildren() {
        lock.readLock().lock();
        try {
            lastAccessTime = System.currentTimeMillis();
            return new ArrayList<>(children.values());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Get a specific child
     *
     * @param name child name
     * @return file info or null if not found
     */
    public FileInfo getChild(String name) {
        lock.readLock().lock();
        try {
            lastAccessTime = System.currentTimeMillis();
            return children.get(name);
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Check if a child exists
     *
     * @param name child name
     * @return true if child exists
     */
    public boolean hasChild(String name) {
        lock.readLock().lock();
        try {
            lastAccessTime = System.currentTimeMillis();
            return children.containsKey(name);
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Check if cache entry is expired
     *
     * @return true if expired
     */
    public boolean isExpired() {
        return System.currentTimeMillis() - lastUpdateTime > maxAge;
    }

    /**
     * Check if cache needs refresh
     *
     * @return true if refresh needed
     */
    public boolean needsRefresh() {
        return isExpired() || hasChanges;
    }

    /**
     * Mark the cache as complete (full enumeration cached)
     */
    public void markComplete() {
        lock.writeLock().lock();
        try {
            this.isComplete = true;
            this.hasChanges = false;
            this.lastUpdateTime = System.currentTimeMillis();
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Invalidate the cache
     */
    public void invalidate() {
        lock.writeLock().lock();
        try {
            children.clear();
            isComplete = false;
            hasChanges = true;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Gets the directory path for this cache entry
     * @return the directory path
     */
    public String getDirectoryPath() {
        return directoryPath;
    }

    /**
     * Gets the lease key associated with this directory cache
     * @return the lease key
     */
    public Smb2LeaseKey getLeaseKey() {
        return leaseKey;
    }

    /**
     * Checks if the complete directory enumeration has been cached
     * @return true if full enumeration is cached
     */
    public boolean isComplete() {
        return isComplete;
    }

    /**
     * Gets the cache scope (ALL or IMMEDIATE_CHILDREN)
     * @return the cache scope
     */
    public DirectoryCacheScope getScope() {
        return scope;
    }

    /**
     * Sets the cache scope for this directory cache
     * @param scope the cache scope to set
     */
    public void setScope(DirectoryCacheScope scope) {
        this.scope = scope;
    }

    /**
     * Gets the maximum age for cached data before requiring refresh
     * @return the maximum cache age in milliseconds
     */
    public long getMaxAge() {
        return maxAge;
    }

    /**
     * Sets the maximum age for cached data
     * @param maxAge the maximum cache age in milliseconds
     */
    public void setMaxAge(long maxAge) {
        this.maxAge = maxAge;
    }

    /**
     * Gets the timestamp when this cache entry was created
     * @return the create time
     */
    public long getCreateTime() {
        return createTime;
    }

    /**
     * Gets the timestamp of the last cache update
     * @return the last update time
     */
    public long getLastUpdateTime() {
        return lastUpdateTime;
    }

    /**
     * Gets the timestamp of the last cache access
     * @return the last access time
     */
    public long getLastAccessTime() {
        return lastAccessTime;
    }

    /**
     * Checks if the cache has pending changes
     * @return true if cache has changes
     */
    public boolean hasChanges() {
        return hasChanges;
    }

    /**
     * Get and increment inconsistency count
     *
     * @return the current inconsistency count
     */
    public int getInconsistencyCount() {
        return inconsistencyCount.getAndIncrement();
    }

    /**
     * Reset inconsistency count
     */
    public void resetInconsistencyCount() {
        inconsistencyCount.set(0);
    }
}