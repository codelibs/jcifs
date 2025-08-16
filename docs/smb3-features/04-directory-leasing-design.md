# Directory Leasing Feature - Detailed Design Document

## 1. Overview

Directory leasing extends the SMB3 lease concept to directories, enabling client-side caching of directory metadata and change notifications. This significantly improves performance for applications that frequently enumerate directories or monitor directory changes.

## 2. Protocol Specification Reference

- **MS-SMB2 Section 2.2.13.2.12**: SMB2_CREATE_REQUEST_LEASE_V2 for directories
- **MS-SMB2 Section 2.2.14.2.12**: SMB2_CREATE_RESPONSE_LEASE_V2 for directories  
- **MS-SMB2 Section 2.2.35**: SMB2 Change Notify Request
- **MS-SMB2 Section 2.2.36**: SMB2 Change Notify Response
- **MS-SMB2 Section 3.3.5.9.11**: Directory Leasing and Caching

## 3. Directory Lease Types

### 3.1 Directory-Specific Lease States
```java
public class DirectoryLeaseState extends Smb2LeaseState {
    // Standard lease states apply, plus directory-specific semantics:
    
    // READ_CACHING for directories means:
    // - Can cache directory enumeration results
    // - Can cache file existence queries
    // - Can cache basic file attributes
    
    // HANDLE_CACHING for directories means:
    // - Can keep directory handle open
    // - Can cache subdirectory handles
    
    // WRITE_CACHING for directories means:
    // - Can cache file creation/deletion notifications
    // - Can perform optimistic file operations
    
    // Directory-specific combinations
    public static final int DIRECTORY_READ_HANDLE = SMB2_LEASE_READ_CACHING | SMB2_LEASE_HANDLE_CACHING;
    public static final int DIRECTORY_FULL = SMB2_LEASE_FULL;  // All three
}
```

### 3.2 Directory Cache Scopes
```java
public enum DirectoryCacheScope {
    IMMEDIATE_CHILDREN,    // Only direct children
    RECURSIVE_TREE,        // Entire subtree (if supported)
    METADATA_ONLY,         // File attributes but not content
    FULL_ENUMERATION      // Complete directory listing
}
```

## 4. Data Structures

### 4.1 Directory Lease Context
```java
package jcifs.internal.smb2.lease;

public class DirectoryLeaseContext extends Smb2LeaseContext {
    public static final String NAME_DIRECTORY_REQUEST = "DLse";
    public static final String NAME_DIRECTORY_RESPONSE = "DLse";
    
    private DirectoryCacheScope cacheScope;
    private long maxCacheAge;
    private boolean notificationEnabled;
    private int notificationFilter;
    
    // Directory lease flags
    public static final int DIRECTORY_LEASE_FLAG_RECURSIVE = 0x00000001;
    public static final int DIRECTORY_LEASE_FLAG_NOTIFICATIONS = 0x00000002;
    
    public DirectoryLeaseContext(Smb2LeaseKey key, int leaseState, DirectoryCacheScope scope) {
        super();
        setLeaseKey(key);
        setLeaseState(leaseState);
        this.cacheScope = scope;
        this.maxCacheAge = 30000;  // 30 seconds default
        this.notificationEnabled = true;
    }
    
    @Override
    public void encode(byte[] buffer, int offset) {
        super.encode(buffer, offset);
        
        // Add directory-specific data after standard lease context
        int dataOffset = offset + getStandardLeaseSize();
        
        // CacheScope (4 bytes)
        writeInt4(buffer, dataOffset, cacheScope.ordinal());
        dataOffset += 4;
        
        // MaxCacheAge (8 bytes)
        writeInt8(buffer, dataOffset, maxCacheAge);
        dataOffset += 8;
        
        // Flags (4 bytes)
        int flags = 0;
        if (cacheScope == DirectoryCacheScope.RECURSIVE_TREE) {
            flags |= DIRECTORY_LEASE_FLAG_RECURSIVE;
        }
        if (notificationEnabled) {
            flags |= DIRECTORY_LEASE_FLAG_NOTIFICATIONS;
        }
        writeInt4(buffer, dataOffset, flags);
        dataOffset += 4;
        
        // NotificationFilter (4 bytes)
        writeInt4(buffer, dataOffset, notificationFilter);
    }
    
    @Override
    public void decode(byte[] buffer, int offset, int length) {
        super.decode(buffer, offset, length);
        
        if (length > getStandardLeaseSize()) {
            // Decode directory-specific data
            int dataOffset = offset + getStandardLeaseSize();
            
            int scopeOrdinal = readInt4(buffer, dataOffset);
            this.cacheScope = DirectoryCacheScope.values()[scopeOrdinal];
            dataOffset += 4;
            
            this.maxCacheAge = readInt8(buffer, dataOffset);
            dataOffset += 8;
            
            int flags = readInt4(buffer, dataOffset);
            dataOffset += 4;
            
            this.notificationFilter = readInt4(buffer, dataOffset);
        }
    }
}
```

### 4.2 Directory Cache Entry
```java
package jcifs.internal.smb2.lease;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class DirectoryCacheEntry {
    private final String directoryPath;
    private final Smb2LeaseKey leaseKey;
    private final long createTime;
    private volatile long lastUpdateTime;
    private volatile long lastAccessTime;
    
    // Cached directory contents
    private final ConcurrentHashMap<String, FileInfo> children;
    private final ReadWriteLock lock;
    
    // Cache metadata
    private volatile boolean isComplete;  // True if full enumeration cached
    private volatile boolean hasChanges;  // True if changes detected
    private DirectoryCacheScope scope;
    private long maxAge;
    
    public DirectoryCacheEntry(String path, Smb2LeaseKey key, DirectoryCacheScope scope) {
        this.directoryPath = path;
        this.leaseKey = key;
        this.scope = scope;
        this.createTime = System.currentTimeMillis();
        this.lastUpdateTime = createTime;
        this.lastAccessTime = createTime;
        this.maxAge = 30000;  // 30 seconds default
        
        this.children = new ConcurrentHashMap<>();
        this.lock = new ReentrantReadWriteLock();
        this.isComplete = false;
        this.hasChanges = false;
    }
    
    public static class FileInfo {
        private final String name;
        private final long size;
        private final long lastModified;
        private final boolean isDirectory;
        private final long attributes;
        private final long creationTime;
        private final long lastAccessTime;
        
        public FileInfo(String name, SmbFileAttributes attrs) {
            this.name = name;
            this.size = attrs.getSize();
            this.lastModified = attrs.getLastWriteTime();
            this.isDirectory = attrs.isDirectory();
            this.attributes = attrs.getAttributes();
            this.creationTime = attrs.getCreateTime();
            this.lastAccessTime = attrs.getLastAccessTime();
        }
        
        public boolean matches(SmbFileAttributes attrs) {
            return size == attrs.getSize() 
                && lastModified == attrs.getLastWriteTime()
                && attributes == attrs.getAttributes();
        }
    }
    
    public void updateChild(String childName, SmbFileAttributes attrs) {
        lock.writeLock().lock();
        try {
            FileInfo existing = children.get(childName);
            FileInfo newInfo = new FileInfo(childName, attrs);
            
            if (existing == null || !existing.matches(attrs)) {
                children.put(childName, newInfo);
                hasChanges = true;
                lastUpdateTime = System.currentTimeMillis();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }
    
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
    
    public List<FileInfo> getChildren() {
        lock.readLock().lock();
        try {
            lastAccessTime = System.currentTimeMillis();
            return new ArrayList<>(children.values());
        } finally {
            lock.readLock().unlock();
        }
    }
    
    public FileInfo getChild(String name) {
        lock.readLock().lock();
        try {
            lastAccessTime = System.currentTimeMillis();
            return children.get(name);
        } finally {
            lock.readLock().unlock();
        }
    }
    
    public boolean hasChild(String name) {
        lock.readLock().lock();
        try {
            lastAccessTime = System.currentTimeMillis();
            return children.containsKey(name);
        } finally {
            lock.readLock().unlock();
        }
    }
    
    public boolean isExpired() {
        return System.currentTimeMillis() - lastUpdateTime > maxAge;
    }
    
    public boolean needsRefresh() {
        return isExpired() || hasChanges;
    }
    
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
}
```

### 4.3 Directory Lease Manager
```java
package jcifs.internal.smb2.lease;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class DirectoryLeaseManager {
    private final CIFSContext context;
    private final LeaseManager baseLeaseManager;  // Reuse existing lease manager
    private final ConcurrentHashMap<String, DirectoryCacheEntry> directoryCache;
    private final ConcurrentHashMap<Smb2LeaseKey, String> leaseToPath;
    private final ScheduledExecutorService scheduler;
    
    // Change notification integration
    private final DirectoryChangeNotifier changeNotifier;
    
    public DirectoryLeaseManager(CIFSContext context, LeaseManager leaseManager) {
        this.context = context;
        this.baseLeaseManager = leaseManager;
        this.directoryCache = new ConcurrentHashMap<>();
        this.leaseToPath = new ConcurrentHashMap<>();
        this.scheduler = Executors.newScheduledThreadPool(1);
        this.changeNotifier = new DirectoryChangeNotifier(this);
        
        // Schedule periodic cache cleanup
        scheduler.scheduleAtFixedRate(this::cleanupExpiredEntries, 60, 60, TimeUnit.SECONDS);
    }
    
    public Smb2LeaseKey requestDirectoryLease(String directoryPath, 
                                             int requestedState, 
                                             DirectoryCacheScope scope) {
        // Request base lease
        Smb2LeaseKey leaseKey = baseLeaseManager.requestLease(directoryPath, requestedState);
        
        // Create directory cache entry
        DirectoryCacheEntry cacheEntry = new DirectoryCacheEntry(directoryPath, leaseKey, scope);
        directoryCache.put(directoryPath, cacheEntry);
        leaseToPath.put(leaseKey, directoryPath);
        
        // Start change notification if enabled
        if (context.getConfig().isDirectoryNotificationsEnabled()) {
            changeNotifier.startWatching(directoryPath, leaseKey);
        }
        
        return leaseKey;
    }
    
    public DirectoryCacheEntry getCacheEntry(String directoryPath) {
        DirectoryCacheEntry entry = directoryCache.get(directoryPath);
        
        // Check if cache entry is valid
        if (entry != null && entry.needsRefresh()) {
            // Check if lease is still valid
            LeaseEntry leaseEntry = baseLeaseManager.getLease(entry.getLeaseKey());
            if (leaseEntry == null || !leaseEntry.hasReadCache()) {
                // Lease lost, remove cache entry
                directoryCache.remove(directoryPath);
                return null;
            }
        }
        
        return entry;
    }
    
    public boolean canCacheDirectoryListing(String directoryPath) {
        DirectoryCacheEntry entry = getCacheEntry(directoryPath);
        if (entry == null) return false;
        
        LeaseEntry leaseEntry = baseLeaseManager.getLease(entry.getLeaseKey());
        return leaseEntry != null && leaseEntry.hasReadCache();
    }
    
    public List<SmbFile> getCachedDirectoryListing(String directoryPath) {
        DirectoryCacheEntry entry = getCacheEntry(directoryPath);
        if (entry == null || !entry.isComplete()) {
            return null;  // No cached listing available
        }
        
        List<SmbFile> files = new ArrayList<>();
        for (DirectoryCacheEntry.FileInfo fileInfo : entry.getChildren()) {
            // Create SmbFile objects from cached info
            SmbFile file = createSmbFileFromCache(directoryPath, fileInfo);
            files.add(file);
        }
        
        return files;
    }
    
    public void updateDirectoryCache(String directoryPath, List<SmbFile> files) {
        DirectoryCacheEntry entry = getCacheEntry(directoryPath);
        if (entry == null) return;
        
        // Update cache with new directory listing
        for (SmbFile file : files) {
            SmbFileAttributes attrs = file.getAttributes();
            entry.updateChild(file.getName(), attrs);
        }
        
        entry.markComplete();
    }
    
    public void handleDirectoryChange(String directoryPath, String childName, 
                                    DirectoryChangeType changeType) {
        DirectoryCacheEntry entry = directoryCache.get(directoryPath);
        if (entry == null) return;
        
        switch (changeType) {
            case FILE_ADDED:
                // Invalidate cache - we need to fetch new file info
                entry.invalidate();
                break;
                
            case FILE_REMOVED:
                entry.removeChild(childName);
                break;
                
            case FILE_MODIFIED:
                // Remove from cache to force refresh
                entry.removeChild(childName);
                break;
                
            case DIRECTORY_RENAMED:
                // Full invalidation needed
                entry.invalidate();
                break;
        }
    }
    
    public void handleDirectoryLeaseBreak(Smb2LeaseKey leaseKey, int newState) {
        String directoryPath = leaseToPath.get(leaseKey);
        if (directoryPath == null) return;
        
        DirectoryCacheEntry entry = directoryCache.get(directoryPath);
        if (entry == null) return;
        
        // Handle lease break by updating cache behavior
        if ((newState & Smb2LeaseState.SMB2_LEASE_READ_CACHING) == 0) {
            // Lost read cache - invalidate directory cache
            entry.invalidate();
        }
        
        if ((newState & Smb2LeaseState.SMB2_LEASE_HANDLE_CACHING) == 0) {
            // Lost handle cache - may need to close directory handle
            changeNotifier.stopWatching(directoryPath);
        }
        
        // Forward to base lease manager
        baseLeaseManager.handleLeaseBreak(leaseKey, newState);
    }
    
    public void releaseDirectoryLease(String directoryPath) {
        DirectoryCacheEntry entry = directoryCache.remove(directoryPath);
        if (entry != null) {
            leaseToPath.remove(entry.getLeaseKey());
            changeNotifier.stopWatching(directoryPath);
            baseLeaseManager.releaseLease(entry.getLeaseKey());
        }
    }
    
    private void cleanupExpiredEntries() {
        List<String> expiredPaths = new ArrayList<>();
        
        for (Map.Entry<String, DirectoryCacheEntry> entry : directoryCache.entrySet()) {
            if (entry.getValue().isExpired()) {
                expiredPaths.add(entry.getKey());
            }
        }
        
        for (String path : expiredPaths) {
            releaseDirectoryLease(path);
        }
    }
    
    private SmbFile createSmbFileFromCache(String directoryPath, 
                                          DirectoryCacheEntry.FileInfo fileInfo) {
        String filePath = directoryPath + "/" + fileInfo.getName();
        
        // Create SmbFile with cached attributes
        SmbFile file = new SmbFile(filePath, context);
        file.setCachedAttributes(new SmbFileAttributes() {
            @Override
            public long getSize() { return fileInfo.getSize(); }
            @Override
            public long getLastWriteTime() { return fileInfo.getLastModified(); }
            @Override
            public boolean isDirectory() { return fileInfo.isDirectory(); }
            // ... other attribute methods
        });
        
        return file;
    }
}
```

### 4.4 Directory Change Notifier
```java
package jcifs.internal.smb2.lease;

import jcifs.internal.smb2.ServerMessageBlock2;
import java.util.concurrent.ConcurrentHashMap;

public class DirectoryChangeNotifier {
    private final DirectoryLeaseManager leaseManager;
    private final ConcurrentHashMap<String, ChangeNotificationHandle> activeWatchers;
    
    public enum DirectoryChangeType {
        FILE_ADDED,
        FILE_REMOVED,
        FILE_MODIFIED,
        DIRECTORY_RENAMED,
        ATTRIBUTES_CHANGED
    }
    
    public static class ChangeNotificationHandle {
        private final String directoryPath;
        private final Smb2LeaseKey leaseKey;
        private final SmbFile directoryFile;
        private volatile boolean active;
        
        public ChangeNotificationHandle(String path, Smb2LeaseKey key, SmbFile dir) {
            this.directoryPath = path;
            this.leaseKey = key;
            this.directoryFile = dir;
            this.active = true;
        }
    }
    
    public DirectoryChangeNotifier(DirectoryLeaseManager manager) {
        this.leaseManager = manager;
        this.activeWatchers = new ConcurrentHashMap<>();
    }
    
    public void startWatching(String directoryPath, Smb2LeaseKey leaseKey) {
        if (activeWatchers.containsKey(directoryPath)) {
            return;  // Already watching
        }
        
        try {
            SmbFile directory = new SmbFile(directoryPath, leaseManager.getContext());
            ChangeNotificationHandle handle = new ChangeNotificationHandle(
                directoryPath, leaseKey, directory);
            
            activeWatchers.put(directoryPath, handle);
            
            // Start async change notification
            startAsyncNotification(handle);
            
        } catch (Exception e) {
            log.error("Failed to start directory watching for: " + directoryPath, e);
        }
    }
    
    public void stopWatching(String directoryPath) {
        ChangeNotificationHandle handle = activeWatchers.remove(directoryPath);
        if (handle != null) {
            handle.active = false;
            // Cancel any pending notifications
            cancelNotification(handle);
        }
    }
    
    private void startAsyncNotification(ChangeNotificationHandle handle) {
        CompletableFuture.runAsync(() -> {
            while (handle.active) {
                try {
                    // Send SMB2 Change Notify request
                    Smb2ChangeNotifyRequest request = new Smb2ChangeNotifyRequest();
                    request.setFileId(handle.directoryFile.getFileId());
                    request.setCompletionFilter(getNotificationFilter());
                    request.setWatchTree(false);  // Non-recursive for now
                    
                    Smb2ChangeNotifyResponse response = (Smb2ChangeNotifyResponse) 
                        handle.directoryFile.getTree().send(request);
                    
                    if (response.isSuccess()) {
                        processChangeNotification(handle, response);
                    }
                    
                } catch (Exception e) {
                    if (handle.active) {
                        log.debug("Change notification failed for: " + handle.directoryPath, e);
                        // Retry after delay
                        try {
                            Thread.sleep(5000);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                    }
                }
            }
        });
    }
    
    private void processChangeNotification(ChangeNotificationHandle handle, 
                                         Smb2ChangeNotifyResponse response) {
        // Parse FILE_NOTIFY_INFORMATION structures from response
        byte[] data = response.getOutputBuffer();
        int offset = 0;
        
        while (offset < data.length) {
            int nextEntryOffset = readInt4(data, offset);
            int action = readInt4(data, offset + 4);
            int fileNameLength = readInt4(data, offset + 8);
            
            // Extract filename
            byte[] fileNameBytes = new byte[fileNameLength];
            System.arraycopy(data, offset + 12, fileNameBytes, 0, fileNameLength);
            String fileName = new String(fileNameBytes, StandardCharsets.UTF_16LE);
            
            // Convert action to our enum
            DirectoryChangeType changeType = convertAction(action);
            
            // Notify lease manager
            leaseManager.handleDirectoryChange(handle.directoryPath, fileName, changeType);
            
            if (nextEntryOffset == 0) break;
            offset += nextEntryOffset;
        }
    }
    
    private DirectoryChangeType convertAction(int action) {
        switch (action) {
            case FILE_ACTION_ADDED: return DirectoryChangeType.FILE_ADDED;
            case FILE_ACTION_REMOVED: return DirectoryChangeType.FILE_REMOVED;
            case FILE_ACTION_MODIFIED: return DirectoryChangeType.FILE_MODIFIED;
            case FILE_ACTION_RENAMED_OLD_NAME:
            case FILE_ACTION_RENAMED_NEW_NAME: return DirectoryChangeType.DIRECTORY_RENAMED;
            default: return DirectoryChangeType.ATTRIBUTES_CHANGED;
        }
    }
    
    private int getNotificationFilter() {
        return FILE_NOTIFY_CHANGE_FILE_NAME
             | FILE_NOTIFY_CHANGE_DIR_NAME
             | FILE_NOTIFY_CHANGE_ATTRIBUTES
             | FILE_NOTIFY_CHANGE_SIZE
             | FILE_NOTIFY_CHANGE_LAST_WRITE;
    }
    
    // SMB2 Change Notify constants
    private static final int FILE_ACTION_ADDED = 0x00000001;
    private static final int FILE_ACTION_REMOVED = 0x00000002;
    private static final int FILE_ACTION_MODIFIED = 0x00000003;
    private static final int FILE_ACTION_RENAMED_OLD_NAME = 0x00000004;
    private static final int FILE_ACTION_RENAMED_NEW_NAME = 0x00000005;
    
    private static final int FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001;
    private static final int FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002;
    private static final int FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004;
    private static final int FILE_NOTIFY_CHANGE_SIZE = 0x00000008;
    private static final int FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010;
}
```

## 5. Integration with Existing Code

### 5.1 SmbFile Directory Operations
```java
// In SmbFile.java
private DirectoryLeaseManager directoryLeaseManager;
private Smb2LeaseKey directoryLeaseKey;

@Override
public SmbFile[] listFiles() throws IOException {
    if (!isDirectory()) {
        throw new IOException("Not a directory");
    }
    
    // Check if we can use cached directory listing
    if (directoryLeaseManager != null && 
        directoryLeaseManager.canCacheDirectoryListing(getPath())) {
        
        List<SmbFile> cachedFiles = directoryLeaseManager.getCachedDirectoryListing(getPath());
        if (cachedFiles != null) {
            log.debug("Using cached directory listing for: {}", getPath());
            return cachedFiles.toArray(new SmbFile[0]);
        }
    }
    
    // Perform actual directory enumeration
    SmbFile[] files = performDirectoryEnumeration();
    
    // Update cache if we have a directory lease
    if (directoryLeaseManager != null && directoryLeaseKey != null) {
        directoryLeaseManager.updateDirectoryCache(getPath(), Arrays.asList(files));
    }
    
    return files;
}

@Override
public boolean exists() throws IOException {
    if (isDirectory() && directoryLeaseManager != null) {
        // Check parent directory cache first
        String parentPath = getParent();
        DirectoryCacheEntry parentCache = directoryLeaseManager.getCacheEntry(parentPath);
        
        if (parentCache != null && parentCache.isComplete()) {
            boolean exists = parentCache.hasChild(getName());
            log.debug("Using cached existence check for: {}", getPath());
            return exists;
        }
    }
    
    // Fall back to regular existence check
    return super.exists();
}

private void requestDirectoryLease() {
    if (!isDirectory() || !context.getConfig().isUseDirectoryLeasing()) {
        return;
    }
    
    if (!tree.getSession().supports(SMB3_0)) {
        return;  // Directory leasing requires SMB3
    }
    
    directoryLeaseManager = tree.getSession().getDirectoryLeaseManager();
    if (directoryLeaseManager != null) {
        DirectoryCacheScope scope = context.getConfig().getDirectoryCacheScope();
        int requestedState = DirectoryLeaseState.DIRECTORY_READ_HANDLE;
        
        directoryLeaseKey = directoryLeaseManager.requestDirectoryLease(
            getPath(), requestedState, scope);
        
        // Add directory lease context to create request
        if (createRequest != null) {
            DirectoryLeaseContext leaseCtx = new DirectoryLeaseContext(
                directoryLeaseKey, requestedState, scope);
            createRequest.addCreateContext(leaseCtx);
        }
    }
}

@Override
protected void doConnect() throws IOException {
    // Request directory lease for directories
    if (isDirectory()) {
        requestDirectoryLease();
    }
    
    // Continue with normal connection logic
    super.doConnect();
}

@Override
public void close() throws IOException {
    try {
        super.close();
    } finally {
        // Don't release directory lease on close - it may be shared
        // Lease will be cleaned up by the lease manager
    }
}
```

### 5.2 Session Integration
```java
// In SmbSession.java
private DirectoryLeaseManager directoryLeaseManager;

public void initializeDirectoryLeasing() {
    if (context.getConfig().isUseDirectoryLeasing() && supports(SMB3_0)) {
        directoryLeaseManager = new DirectoryLeaseManager(context, leaseManager);
    }
}

public DirectoryLeaseManager getDirectoryLeaseManager() {
    return directoryLeaseManager;
}

@Override
public void logoff() throws IOException {
    if (directoryLeaseManager != null) {
        directoryLeaseManager.shutdown();
    }
    super.logoff();
}
```

## 6. Configuration

### 6.1 Configuration Properties
```java
// In PropertyConfiguration.java
public static final String USE_DIRECTORY_LEASING = "jcifs.smb.client.useDirectoryLeasing";
public static final String DIRECTORY_CACHE_SCOPE = "jcifs.smb.client.directoryCacheScope";
public static final String DIRECTORY_CACHE_TIMEOUT = "jcifs.smb.client.directoryCacheTimeout";
public static final String DIRECTORY_NOTIFICATIONS_ENABLED = "jcifs.smb.client.directoryNotificationsEnabled";
public static final String MAX_DIRECTORY_CACHE_ENTRIES = "jcifs.smb.client.maxDirectoryCacheEntries";

public boolean isUseDirectoryLeasing() {
    return getBooleanProperty(USE_DIRECTORY_LEASING, true);
}

public DirectoryCacheScope getDirectoryCacheScope() {
    String scope = getProperty(DIRECTORY_CACHE_SCOPE, "IMMEDIATE_CHILDREN");
    return DirectoryCacheScope.valueOf(scope);
}

public long getDirectoryCacheTimeout() {
    return getLongProperty(DIRECTORY_CACHE_TIMEOUT, 30000);  // 30 seconds
}

public boolean isDirectoryNotificationsEnabled() {
    return getBooleanProperty(DIRECTORY_NOTIFICATIONS_ENABLED, true);
}

public int getMaxDirectoryCacheEntries() {
    return getIntProperty(MAX_DIRECTORY_CACHE_ENTRIES, 1000);
}
```

## 7. Performance Optimizations

### 7.1 Batch Directory Operations
```java
public class BatchDirectoryOperations {
    private final DirectoryLeaseManager leaseManager;
    
    public List<SmbFile> batchExists(List<String> paths) {
        // Group paths by parent directory
        Map<String, List<String>> pathsByParent = paths.stream()
            .collect(Collectors.groupingBy(this::getParentPath));
        
        List<SmbFile> results = new ArrayList<>();
        
        for (Map.Entry<String, List<String>> entry : pathsByParent.entrySet()) {
            String parentPath = entry.getKey();
            List<String> childNames = entry.getValue().stream()
                .map(this::getFileName)
                .collect(Collectors.toList());
            
            // Check if we have cached directory info
            DirectoryCacheEntry cache = leaseManager.getCacheEntry(parentPath);
            if (cache != null && cache.isComplete()) {
                // Use cached data for all children
                for (String childName : childNames) {
                    boolean exists = cache.hasChild(childName);
                    if (exists) {
                        results.add(new SmbFile(parentPath + "/" + childName, context));
                    }
                }
            } else {
                // Fall back to individual checks
                for (String path : entry.getValue()) {
                    try {
                        SmbFile file = new SmbFile(path, context);
                        if (file.exists()) {
                            results.add(file);
                        }
                    } catch (IOException e) {
                        log.debug("Error checking existence of: " + path, e);
                    }
                }
            }
        }
        
        return results;
    }
}
```

### 7.2 Hierarchical Cache Management
```java
public class HierarchicalCacheManager {
    private final DirectoryLeaseManager leaseManager;
    private final Map<String, Set<String>> parentChildMap;
    
    public void invalidateHierarchy(String path) {
        // Invalidate all parent directories up to root
        String currentPath = path;
        while (currentPath != null && !currentPath.isEmpty()) {
            DirectoryCacheEntry entry = leaseManager.getCacheEntry(currentPath);
            if (entry != null) {
                entry.invalidate();
            }
            currentPath = getParentPath(currentPath);
        }
        
        // Invalidate all child directories
        invalidateChildren(path);
    }
    
    private void invalidateChildren(String parentPath) {
        Set<String> children = parentChildMap.get(parentPath);
        if (children != null) {
            for (String child : children) {
                DirectoryCacheEntry entry = leaseManager.getCacheEntry(child);
                if (entry != null) {
                    entry.invalidate();
                }
                invalidateChildren(child);  // Recursive
            }
        }
    }
}
```

## 8. Testing Strategy

### 8.1 Unit Tests
```java
@Test
public void testDirectoryCacheEntry() {
    DirectoryCacheEntry entry = new DirectoryCacheEntry(
        "/test/dir", new Smb2LeaseKey(), DirectoryCacheScope.IMMEDIATE_CHILDREN);
    
    // Test adding children
    SmbFileAttributes attrs = createMockAttributes("file1.txt", 1000, false);
    entry.updateChild("file1.txt", attrs);
    
    assertTrue(entry.hasChild("file1.txt"));
    assertEquals(1, entry.getChildren().size());
    
    // Test removal
    entry.removeChild("file1.txt");
    assertFalse(entry.hasChild("file1.txt"));
    assertEquals(0, entry.getChildren().size());
}

@Test
public void testDirectoryLeaseManager() {
    CIFSContext context = new BaseContext(new PropertyConfiguration());
    LeaseManager baseManager = new LeaseManager(context);
    DirectoryLeaseManager dirManager = new DirectoryLeaseManager(context, baseManager);
    
    // Request directory lease
    Smb2LeaseKey key = dirManager.requestDirectoryLease(
        "/test/dir", 
        DirectoryLeaseState.DIRECTORY_READ_HANDLE,
        DirectoryCacheScope.IMMEDIATE_CHILDREN
    );
    
    assertNotNull(key);
    assertTrue(dirManager.canCacheDirectoryListing("/test/dir"));
    
    // Test cache operations
    List<SmbFile> files = Arrays.asList(
        createMockSmbFile("/test/dir/file1.txt"),
        createMockSmbFile("/test/dir/file2.txt")
    );
    
    dirManager.updateDirectoryCache("/test/dir", files);
    
    List<SmbFile> cached = dirManager.getCachedDirectoryListing("/test/dir");
    assertNotNull(cached);
    assertEquals(2, cached.size());
}
```

### 8.2 Integration Tests
```java
@Test
public void testDirectoryListingCache() throws Exception {
    CIFSContext context = getTestContext();
    context.getConfig().setProperty("jcifs.smb.client.useDirectoryLeasing", "true");
    
    SmbFile dir = new SmbFile("smb://server/share/testdir/", context);
    
    // First listing should hit the server
    long start1 = System.currentTimeMillis();
    SmbFile[] files1 = dir.listFiles();
    long time1 = System.currentTimeMillis() - start1;
    
    // Second listing should use cache (much faster)
    long start2 = System.currentTimeMillis();
    SmbFile[] files2 = dir.listFiles();
    long time2 = System.currentTimeMillis() - start2;
    
    assertEquals(files1.length, files2.length);
    assertTrue(time2 < time1 / 2);  // Should be significantly faster
}

@Test
public void testDirectoryChangeNotification() throws Exception {
    CIFSContext context = getTestContext();
    context.getConfig().setProperty("jcifs.smb.client.directoryNotificationsEnabled", "true");
    
    SmbFile dir = new SmbFile("smb://server/share/testdir/", context);
    SmbFile testFile = new SmbFile("smb://server/share/testdir/newfile.txt", context);
    
    // Get initial listing (establishes cache)
    SmbFile[] initialFiles = dir.listFiles();
    
    // Create new file
    testFile.createNewFile();
    
    // Wait for change notification
    Thread.sleep(2000);
    
    // Cache should be invalidated, new listing should include new file
    SmbFile[] updatedFiles = dir.listFiles();
    assertEquals(initialFiles.length + 1, updatedFiles.length);
}
```

## 9. Error Handling

### 9.1 Cache Consistency
```java
public class CacheConsistencyManager {
    public void handleInconsistency(String directoryPath, String fileName) {
        log.warn("Cache inconsistency detected for: {}/{}", directoryPath, fileName);
        
        // Invalidate affected cache entries
        DirectoryCacheEntry entry = leaseManager.getCacheEntry(directoryPath);
        if (entry != null) {
            entry.removeChild(fileName);
            
            // If too many inconsistencies, invalidate entire cache
            if (entry.getInconsistencyCount() > 5) {
                entry.invalidate();
            }
        }
    }
}
```

### 9.2 Fallback Mechanisms
```java
public class DirectoryOperationFallback {
    public SmbFile[] safeListFiles(SmbFile directory) throws IOException {
        try {
            // Try cached listing first
            if (directoryLeaseManager != null) {
                List<SmbFile> cached = directoryLeaseManager.getCachedDirectoryListing(
                    directory.getPath());
                if (cached != null) {
                    return cached.toArray(new SmbFile[0]);
                }
            }
        } catch (Exception e) {
            log.debug("Cached directory listing failed, falling back to direct query", e);
        }
        
        // Fall back to direct server query
        return directory.performDirectEnumeration();
    }
}
```

## 10. Monitoring and Metrics

### 10.1 Directory Cache Statistics
```java
public class DirectoryCacheStatistics {
    private final AtomicLong cacheHits = new AtomicLong();
    private final AtomicLong cacheMisses = new AtomicLong();
    private final AtomicLong cacheInvalidations = new AtomicLong();
    private final AtomicLong changeNotifications = new AtomicLong();
    
    public double getCacheHitRatio() {
        long hits = cacheHits.get();
        long misses = cacheMisses.get();
        long total = hits + misses;
        
        if (total == 0) return 0.0;
        return (double) hits / total;
    }
    
    public void recordCacheHit() { cacheHits.incrementAndGet(); }
    public void recordCacheMiss() { cacheMisses.incrementAndGet(); }
    public void recordInvalidation() { cacheInvalidations.incrementAndGet(); }
    public void recordChangeNotification() { changeNotifications.incrementAndGet(); }
}
```