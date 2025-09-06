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
package org.codelibs.jcifs.smb.internal.smb2.persistent;

import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.internal.smb2.lease.Smb2LeaseKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manager for persistent and durable SMB handles.
 *
 * This class provides:
 * - Handle lifecycle management
 * - Persistent storage for persistent handles
 * - Expiration tracking for durable handles
 * - Thread-safe access to handle information
 */
public class PersistentHandleManager {

    private static final Logger log = LoggerFactory.getLogger(PersistentHandleManager.class);

    private final ConcurrentHashMap<String, HandleInfo> handles;
    private final ConcurrentHashMap<HandleGuid, HandleInfo> guidToHandle;
    private final Path stateDirectory;
    private final ScheduledExecutorService scheduler;
    private final CIFSContext context;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    private volatile boolean shutdown = false;

    /**
     * Create a new persistent handle manager
     * @param context the CIFS context
     */
    public PersistentHandleManager(CIFSContext context) {
        this.context = context;
        this.handles = new ConcurrentHashMap<>();
        this.guidToHandle = new ConcurrentHashMap<>();
        this.scheduler = Executors.newScheduledThreadPool(1, r -> {
            Thread t = new Thread(r, "PersistentHandleManager");
            t.setDaemon(true);
            return t;
        });

        // Create state directory for persistent storage
        String stateDir = System.getProperty("jcifs.client.handleStateDirectory");
        if (stateDir == null) {
            String homeDir = System.getProperty("user.home");
            stateDir = homeDir + File.separator + ".org.codelibs.jcifs.smb" + File.separator + "handles";
        }
        this.stateDirectory = Paths.get(stateDir);

        try {
            Files.createDirectories(stateDirectory);
        } catch (IOException e) {
            log.error("Failed to create handle state directory: " + stateDirectory, e);
        }

        // Load persisted handles on startup
        loadPersistedHandles();

        // Schedule periodic persistence and cleanup
        scheduler.scheduleAtFixedRate(this::periodicMaintenance, 30, 30, TimeUnit.SECONDS);
    }

    /**
     * Request a new durable handle
     * @param path the file path
     * @param type the handle type
     * @param timeout the timeout in milliseconds
     * @param leaseKey the associated lease key (can be null)
     * @return the handle GUID
     */
    public HandleGuid requestDurableHandle(String path, HandleType type, long timeout, Smb2LeaseKey leaseKey) {
        HandleGuid guid = new HandleGuid();

        // Create handle info with empty file ID (will be populated after successful create response)
        HandleInfo info = new HandleInfo(path, guid, new byte[16], type, timeout, leaseKey);

        lock.writeLock().lock();
        try {
            handles.put(path, info);
            guidToHandle.put(guid, info);

            if (type == HandleType.PERSISTENT) {
                persistHandle(info);
            }
        } finally {
            lock.writeLock().unlock();
        }

        log.debug("Requested {} handle for path: {}", type, path);
        return guid;
    }

    /**
     * Update the file ID for a handle after successful create response
     * @param guid the handle GUID
     * @param fileId the 16-byte file ID
     */
    public void updateHandleFileId(HandleGuid guid, byte[] fileId) {
        lock.writeLock().lock();
        try {
            HandleInfo info = guidToHandle.get(guid);
            if (info != null) {
                info.updateFileId(fileId);
                if (info.getType() == HandleType.PERSISTENT) {
                    persistHandle(info);
                }
                log.debug("Updated file ID for handle: {}", guid);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Get handle information for reconnection
     * @param path the file path
     * @return the handle info if available and not expired, null otherwise
     */
    public HandleInfo getHandleForReconnect(String path) {
        lock.readLock().lock();
        try {
            HandleInfo info = handles.get(path);
            if (info != null && !info.isExpired()) {
                info.setReconnecting(true);
                info.updateAccessTime();
                log.debug("Found handle for reconnect: {}", path);
                return info;
            }
            return null;
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Complete a reconnection attempt
     * @param path the file path
     * @param success true if reconnection was successful
     */
    public void completeReconnect(String path, boolean success) {
        lock.writeLock().lock();
        try {
            HandleInfo info = handles.get(path);
            if (info != null) {
                if (success) {
                    info.updateAccessTime();
                    info.setReconnecting(false);
                    log.info("Reconnection successful for: {}", path);
                } else {
                    // Remove failed handle
                    handles.remove(path);
                    guidToHandle.remove(info.getCreateGuid());
                    removePersistedHandle(info);
                    log.warn("Reconnection failed, removed handle for: {}", path);
                }
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Release a handle
     * @param path the file path
     */
    public void releaseHandle(String path) {
        lock.writeLock().lock();
        try {
            HandleInfo info = handles.remove(path);
            if (info != null) {
                guidToHandle.remove(info.getCreateGuid());
                removePersistedHandle(info);
                log.debug("Released handle for: {}", path);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Get handle information by GUID
     * @param guid the handle GUID
     * @return the handle info or null if not found
     */
    public HandleInfo getHandleByGuid(HandleGuid guid) {
        lock.readLock().lock();
        try {
            return guidToHandle.get(guid);
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Get handle information by path
     * @param path the file path
     * @return the handle info or null if not found
     */
    public HandleInfo getHandleByPath(String path) {
        lock.readLock().lock();
        try {
            return handles.get(path);
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Get the number of active handles
     * @return the number of handles
     */
    public int getHandleCount() {
        return handles.size();
    }

    private void periodicMaintenance() {
        if (shutdown) {
            return;
        }

        lock.writeLock().lock();
        try {
            // Clean up expired handles
            handles.entrySet().removeIf(entry -> {
                HandleInfo info = entry.getValue();
                if (info.isExpired() && !info.isReconnecting()) {
                    guidToHandle.remove(info.getCreateGuid());
                    removePersistedHandle(info);
                    log.debug("Removed expired handle: {}", info.getPath());
                    return true;
                }
                return false;
            });

            // Persist all persistent handles
            for (HandleInfo info : handles.values()) {
                if (info.getType() == HandleType.PERSISTENT && !info.isReconnecting()) {
                    persistHandle(info);
                }
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    private void persistHandle(HandleInfo info) {
        if (info.getType() != HandleType.PERSISTENT) {
            return;
        }

        Path handleFile = stateDirectory.resolve(info.getCreateGuid().toString() + ".handle");
        try (ObjectOutputStream oos = new ObjectOutputStream(Files.newOutputStream(handleFile, StandardOpenOption.CREATE,
                StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING))) {
            oos.writeObject(info);
            log.debug("Persisted handle: {}", info.getPath());
        } catch (IOException e) {
            log.error("Failed to persist handle: " + info.getPath(), e);
        }
    }

    private void removePersistedHandle(HandleInfo info) {
        if (info.getType() != HandleType.PERSISTENT) {
            return;
        }

        Path handleFile = stateDirectory.resolve(info.getCreateGuid().toString() + ".handle");
        try {
            Files.deleteIfExists(handleFile);
            log.debug("Removed persisted handle file: {}", handleFile);
        } catch (IOException e) {
            log.error("Failed to remove persisted handle file: " + handleFile, e);
        }
    }

    private void loadPersistedHandles() {
        if (!Files.exists(stateDirectory)) {
            return;
        }

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(stateDirectory, "*.handle")) {
            for (Path handleFile : stream) {
                try (ObjectInputStream ois = new ObjectInputStream(Files.newInputStream(handleFile))) {
                    HandleInfo info = (HandleInfo) ois.readObject();

                    // Only load if not expired
                    if (!info.isExpired()) {
                        handles.put(info.getPath(), info);
                        guidToHandle.put(info.getCreateGuid(), info);
                        log.info("Loaded persisted handle: {}", info.getPath());
                    } else {
                        Files.delete(handleFile);
                        log.debug("Deleted expired persisted handle: {}", handleFile);
                    }
                } catch (Exception e) {
                    log.error("Failed to load handle file: " + handleFile, e);
                    try {
                        Files.deleteIfExists(handleFile);
                    } catch (IOException deleteEx) {
                        log.error("Failed to delete corrupted handle file: " + handleFile, deleteEx);
                    }
                }
            }
        } catch (IOException e) {
            log.error("Failed to load persisted handles from directory: " + stateDirectory, e);
        }
    }

    /**
     * Get existing handle data for reconnection
     * @param path the file path
     * @return the file ID if available, null otherwise
     */
    public byte[] getExistingHandle(String path) {
        HandleInfo info = getHandleForReconnect(path);
        return info != null ? info.getFileId() : null;
    }

    /**
     * Store handle information after successful create
     * @param path the file path
     * @param fileId the 16-byte file ID
     * @param guid the handle GUID
     */
    public void storeHandle(String path, byte[] fileId, HandleGuid guid) {
        lock.writeLock().lock();
        try {
            HandleInfo info = guidToHandle.get(guid);
            if (info != null) {
                info.updateFileId(fileId);
                if (info.getType() == HandleType.PERSISTENT) {
                    persistHandle(info);
                }
                log.debug("Stored handle for path: {}", path);
            } else {
                // Create new handle info if not found
                HandleInfo newInfo =
                        new HandleInfo(path, guid, fileId, HandleType.PERSISTENT, context.getConfig().getPersistentHandleTimeout(), null);
                handles.put(path, newInfo);
                guidToHandle.put(guid, newInfo);
                persistHandle(newInfo);
                log.debug("Created and stored new handle for path: {}", path);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Shuts down the persistent handle manager and its background tasks
     */
    public void shutdown() {
        shutdown = true;
        scheduler.shutdown();
    }
}
