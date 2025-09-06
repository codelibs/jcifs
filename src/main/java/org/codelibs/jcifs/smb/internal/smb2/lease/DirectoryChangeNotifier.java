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
package org.codelibs.jcifs.smb.internal.smb2.lease;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

import org.codelibs.jcifs.smb.SmbFile;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles directory change notifications for SMB3 directory leasing
 */
public class DirectoryChangeNotifier {

    private static final Logger log = LoggerFactory.getLogger(DirectoryChangeNotifier.class);

    // Backoff and timing constants (in ms)
    private static final long BASE_POLL_INTERVAL = 1000;
    private static final long MAX_POLL_INTERVAL = 30000;
    private static final long BASE_RETRY_DELAY = 1000;
    private static final long MAX_RETRY_DELAY = 30000;
    private static final int MAX_BACKOFF_SHIFT = 3; // Maximum 8 seconds (2^3 * 1000ms)

    private final DirectoryLeaseManager leaseManager;
    private final ConcurrentHashMap<String, ChangeNotificationHandle> activeWatchers;
    private final ConcurrentHashMap<String, Integer> failureCounts;

    /**
     * Directory change types
     */
    public enum DirectoryChangeType {
        /**
         * File was added to the directory
         */
        FILE_ADDED,
        /**
         * File was removed from the directory
         */
        FILE_REMOVED,
        /**
         * File was modified in the directory
         */
        FILE_MODIFIED,
        /**
         * Directory was renamed
         */
        DIRECTORY_RENAMED,
        /**
         * File or directory attributes were changed
         */
        ATTRIBUTES_CHANGED
    }

    /**
     * SMB2 File Action constants
     */
    private static final int FILE_ACTION_ADDED = 0x00000001;
    private static final int FILE_ACTION_REMOVED = 0x00000002;
    private static final int FILE_ACTION_MODIFIED = 0x00000003;
    private static final int FILE_ACTION_RENAMED_OLD_NAME = 0x00000004;
    private static final int FILE_ACTION_RENAMED_NEW_NAME = 0x00000005;

    /**
     * SMB2 File Notify Change constants
     */
    private static final int FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001;
    private static final int FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002;
    private static final int FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004;
    private static final int FILE_NOTIFY_CHANGE_SIZE = 0x00000008;
    private static final int FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010;

    /**
     * Change notification handle
     */
    public static class ChangeNotificationHandle {
        private final String directoryPath;
        private final Smb2LeaseKey leaseKey;
        private final SmbFile directoryFile;
        private volatile boolean active;
        private CompletableFuture<Void> notificationFuture;

        /**
         * Create a new change notification handle
         *
         * @param path directory path
         * @param key lease key
         * @param dir directory file
         */
        public ChangeNotificationHandle(String path, Smb2LeaseKey key, SmbFile dir) {
            this.directoryPath = path;
            this.leaseKey = key;
            this.directoryFile = dir;
            this.active = true;
        }

        /**
         * Gets the path of the directory being monitored
         * @return the directory path
         */
        public String getDirectoryPath() {
            return directoryPath;
        }

        /**
         * Gets the lease key associated with this notification handle
         * @return the lease key
         */
        public Smb2LeaseKey getLeaseKey() {
            return leaseKey;
        }

        /**
         * Gets the SMB file handle for the monitored directory
         * @return the directory file
         */
        public SmbFile getDirectoryFile() {
            return directoryFile;
        }

        /**
         * Checks if directory change monitoring is currently active
         * @return true if watching is active
         */
        public boolean isActive() {
            return active;
        }

        /**
         * Set active status
         *
         * @param active true to activate
         */
        public void setActive(boolean active) {
            this.active = active;
        }

        /**
         * Gets the future for asynchronous notification completion
         * @return the notification future
         */
        public CompletableFuture<Void> getNotificationFuture() {
            return notificationFuture;
        }

        /**
         * Sets the future for asynchronous notification completion
         * @param future the notification future to set
         */
        public void setNotificationFuture(CompletableFuture<Void> future) {
            this.notificationFuture = future;
        }
    }

    /**
     * Create a new directory change notifier
     *
     * @param manager directory lease manager
     */
    public DirectoryChangeNotifier(DirectoryLeaseManager manager) {
        this.leaseManager = manager;
        this.activeWatchers = new ConcurrentHashMap<>();
        this.failureCounts = new ConcurrentHashMap<>();
    }

    /**
     * Start watching a directory for changes
     *
     * @param directoryPath directory path
     * @param leaseKey lease key
     */
    public void startWatching(String directoryPath, Smb2LeaseKey leaseKey) {
        if (activeWatchers.containsKey(directoryPath)) {
            return; // Already watching
        }

        try {
            SmbFile directory = new SmbFile(directoryPath, leaseManager.getContext());
            ChangeNotificationHandle handle = new ChangeNotificationHandle(directoryPath, leaseKey, directory);

            activeWatchers.put(directoryPath, handle);

            // Start async change notification
            startAsyncNotification(handle);

        } catch (Exception e) {
            log.error("Failed to start directory watching for: " + directoryPath, e);
        }
    }

    /**
     * Stop watching a directory
     *
     * @param directoryPath directory path
     */
    public void stopWatching(String directoryPath) {
        ChangeNotificationHandle handle = activeWatchers.remove(directoryPath);
        if (handle != null) {
            handle.setActive(false);
            // Cancel any pending notifications
            cancelNotification(handle);
            // Clean up failure count to prevent memory leak
            failureCounts.remove(directoryPath);
        }
    }

    /**
     * Start asynchronous notification monitoring
     *
     * @param handle notification handle
     */
    private void startAsyncNotification(ChangeNotificationHandle handle) {
        CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
            while (handle.isActive()) {
                try {
                    // Note: Actual SMB2 Change Notify implementation would go here
                    // For now, this is a placeholder that simulates monitoring

                    // In a real implementation, we would:
                    // 1. Send SMB2 Change Notify request
                    // 2. Wait for response
                    // 3. Process changes
                    // 4. Notify the lease manager

                    // Use adaptive polling interval based on activity
                    long pollInterval = determinePollInterval(handle);
                    Thread.sleep(pollInterval);

                    // Check if still active
                    if (!handle.isActive()) {
                        break;
                    }

                    // In a real implementation, we would process actual change notifications here

                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    if (handle.isActive()) {
                        log.debug("Change notification failed for: " + handle.getDirectoryPath(), e);
                        incrementFailureCount(handle);
                        // Exponential backoff with max 8 seconds delay (up to MAX_RETRY_DELAY)
                        try {
                            long retryDelay = Math.min(MAX_RETRY_DELAY,
                                    BASE_RETRY_DELAY * (1L << Math.min(MAX_BACKOFF_SHIFT, getFailureCount(handle))));
                            Thread.sleep(retryDelay);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                    }
                }
            }
        });

        handle.setNotificationFuture(future);
    }

    /**
     * Determine optimal polling interval based on directory activity and failure count
     *
     * Current strategy is based on failure count. In the future, this could be enhanced to consider:
     * - Recent event frequency (successful notifications)
     * - Time since last successful notification
     * - Events per unit time for more adaptive behavior
     *
     * @param handle notification handle
     * @return polling interval in milliseconds
     */
    private long determinePollInterval(ChangeNotificationHandle handle) {
        int failures = getFailureCount(handle);

        // Base interval starts at 1 second, increases with failures
        // Max interval is 30 seconds for inactive directories
        return Math.min(MAX_POLL_INTERVAL, BASE_POLL_INTERVAL + (failures * 2000));
    }

    /**
     * Get failure count for a handle
     *
     * @param handle notification handle
     * @return number of consecutive failures
     */
    private int getFailureCount(ChangeNotificationHandle handle) {
        return failureCounts.getOrDefault(handle.getDirectoryPath(), 0);
    }

    /**
     * Increment failure count for a handle
     *
     * @param handle notification handle
     */
    private void incrementFailureCount(ChangeNotificationHandle handle) {
        failureCounts.compute(handle.getDirectoryPath(), (path, count) -> count == null ? 1 : count + 1);
    }

    /**
     * Reset failure count for a handle (called on successful operations)
     *
     * @param handle notification handle
     */
    private void resetFailureCount(ChangeNotificationHandle handle) {
        failureCounts.remove(handle.getDirectoryPath());
    }

    /**
     * Process change notification response
     *
     * @param handle notification handle
     * @param outputBuffer response buffer containing FILE_NOTIFY_INFORMATION structures
     */
    public void processChangeNotification(ChangeNotificationHandle handle, byte[] outputBuffer) {
        if (outputBuffer == null || outputBuffer.length == 0) {
            return;
        }

        int offset = 0;

        while (offset < outputBuffer.length) {
            // Parse FILE_NOTIFY_INFORMATION structure
            int nextEntryOffset = SMBUtil.readInt4(outputBuffer, offset);
            int action = SMBUtil.readInt4(outputBuffer, offset + 4);
            int fileNameLength = SMBUtil.readInt4(outputBuffer, offset + 8);

            // Extract filename
            byte[] fileNameBytes = new byte[fileNameLength];
            System.arraycopy(outputBuffer, offset + 12, fileNameBytes, 0, fileNameLength);
            String fileName = new String(fileNameBytes, StandardCharsets.UTF_16LE);

            // Convert action to our enum
            DirectoryChangeType changeType = convertAction(action);

            // Reset failure count on successful notification
            resetFailureCount(handle);

            // Notify lease manager
            leaseManager.handleDirectoryChange(handle.getDirectoryPath(), fileName, changeType);

            if (nextEntryOffset == 0) {
                break;
            }
            offset += nextEntryOffset;
        }
    }

    /**
     * Convert SMB2 action to change type
     *
     * @param action SMB2 file action
     * @return directory change type
     */
    private DirectoryChangeType convertAction(int action) {
        switch (action) {
        case FILE_ACTION_ADDED:
            return DirectoryChangeType.FILE_ADDED;
        case FILE_ACTION_REMOVED:
            return DirectoryChangeType.FILE_REMOVED;
        case FILE_ACTION_MODIFIED:
            return DirectoryChangeType.FILE_MODIFIED;
        case FILE_ACTION_RENAMED_OLD_NAME:
        case FILE_ACTION_RENAMED_NEW_NAME:
            return DirectoryChangeType.DIRECTORY_RENAMED;
        default:
            return DirectoryChangeType.ATTRIBUTES_CHANGED;
        }
    }

    /**
     * Get notification filter flags
     *
     * @return filter flags for change notifications
     */
    public int getNotificationFilter() {
        return FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE
                | FILE_NOTIFY_CHANGE_LAST_WRITE;
    }

    /**
     * Cancel notification for a handle
     *
     * @param handle notification handle
     */
    private void cancelNotification(ChangeNotificationHandle handle) {
        CompletableFuture<Void> future = handle.getNotificationFuture();
        if (future != null && !future.isDone()) {
            future.cancel(true);
        }
    }
}