# Persistent Handles Feature - Detailed Design Document

## 1. Overview

Persistent handles (also known as durable handles) allow SMB3 connections to survive network disconnections, server reboots, and client reconnections. This feature is critical for enterprise reliability and seamless failover scenarios.

## 2. Protocol Specification Reference

- **MS-SMB2 Section 2.2.13.2.3**: SMB2_CREATE_DURABLE_HANDLE_REQUEST
- **MS-SMB2 Section 2.2.13.2.4**: SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2
- **MS-SMB2 Section 2.2.13.2.5**: SMB2_CREATE_DURABLE_HANDLE_RECONNECT
- **MS-SMB2 Section 2.2.13.2.12**: SMB2_CREATE_REQUEST_LEASE_V2
- **MS-SMB2 Section 3.2.1.4**: Durable Open Scavenger Timer

## 3. Handle Types and Capabilities

### 3.1 Handle Types
```java
public enum HandleType {
    NONE(0),                    // No durability
    DURABLE_V1(1),              // SMB 2.1 - survives network loss
    DURABLE_V2(2),              // SMB 3.0 - with timeout
    PERSISTENT(3);              // SMB 3.0 - survives server reboot
    
    private final int value;
    
    HandleType(int value) {
        this.value = value;
    }
}
```

### 3.2 Handle Capabilities
```java
public class Smb2HandleCapabilities {
    // Durable handle flags
    public static final int SMB2_DHANDLE_FLAG_PERSISTENT = 0x00000002;
    
    // Timeout values (milliseconds)
    public static final long DEFAULT_DURABLE_TIMEOUT = 120000;  // 2 minutes
    public static final long MAX_DURABLE_TIMEOUT = 300000;      // 5 minutes
    public static final long PERSISTENT_TIMEOUT = 0;            // Infinite for persistent
}
```

## 4. Data Structures

### 4.1 Handle GUID Structure
```java
package jcifs.internal.smb2.persistent;

import java.util.UUID;
import java.nio.ByteBuffer;

public class HandleGuid {
    private final UUID guid;
    
    public HandleGuid() {
        this.guid = UUID.randomUUID();
    }
    
    public HandleGuid(byte[] bytes) {
        if (bytes.length != 16) {
            throw new IllegalArgumentException("GUID must be 16 bytes");
        }
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        long mostSig = bb.getLong();
        long leastSig = bb.getLong();
        this.guid = new UUID(mostSig, leastSig);
    }
    
    public byte[] toBytes() {
        ByteBuffer bb = ByteBuffer.allocate(16);
        bb.putLong(guid.getMostSignificantBits());
        bb.putLong(guid.getLeastSignificantBits());
        return bb.array();
    }
    
    @Override
    public String toString() {
        return guid.toString();
    }
    
    @Override
    public boolean equals(Object obj) {
        if (obj instanceof HandleGuid) {
            return guid.equals(((HandleGuid)obj).guid);
        }
        return false;
    }
    
    @Override
    public int hashCode() {
        return guid.hashCode();
    }
}
```

### 4.2 Durable Handle Request Context
```java
package jcifs.internal.smb2.persistent;

import jcifs.internal.smb2.create.Smb2CreateContext;

public class DurableHandleRequest extends Smb2CreateContext {
    public static final String NAME = "DHnQ";  // Durable Handle Request
    
    private static final int STRUCTURE_SIZE = 16;
    private long reserved;  // Must be zero
    
    public DurableHandleRequest() {
        super(NAME);
        this.reserved = 0;
    }
    
    @Override
    public void encode(byte[] buffer, int offset) {
        // Context header
        int nameLen = getName().length();
        writeInt4(buffer, offset, 16);  // Next
        writeInt2(buffer, offset + 4, nameLen);  // NameOffset
        writeInt2(buffer, offset + 6, nameLen);  // NameLength
        writeInt2(buffer, offset + 8, 0);  // Reserved
        writeInt2(buffer, offset + 10, STRUCTURE_SIZE);  // DataOffset
        writeInt4(buffer, offset + 12, STRUCTURE_SIZE);  // DataLength
        
        // Name
        System.arraycopy(getName().getBytes(), 0, buffer, offset + 16, nameLen);
        
        // Data (16 bytes of reserved)
        int dataOffset = offset + 16 + nameLen;
        dataOffset = (dataOffset + 7) & ~7;  // 8-byte alignment
        
        for (int i = 0; i < 16; i++) {
            buffer[dataOffset + i] = 0;
        }
    }
    
    @Override
    public int size() {
        int nameLen = getName().length();
        return 16 + nameLen + ((8 - (nameLen % 8)) % 8) + STRUCTURE_SIZE;
    }
}
```

### 4.3 Durable Handle V2 Request Context
```java
package jcifs.internal.smb2.persistent;

public class DurableHandleV2Request extends Smb2CreateContext {
    public static final String NAME = "DH2Q";  // Durable Handle V2 Request
    
    private long timeout;
    private int flags;
    private HandleGuid createGuid;
    
    public DurableHandleV2Request(long timeout, boolean persistent) {
        super(NAME);
        this.timeout = timeout;
        this.flags = persistent ? Smb2HandleCapabilities.SMB2_DHANDLE_FLAG_PERSISTENT : 0;
        this.createGuid = new HandleGuid();
    }
    
    @Override
    public void encode(byte[] buffer, int offset) {
        // Context header
        int nameLen = getName().length();
        writeInt4(buffer, offset, 32);  // Next
        writeInt2(buffer, offset + 4, nameLen);  // NameOffset
        writeInt2(buffer, offset + 6, nameLen);  // NameLength
        writeInt2(buffer, offset + 8, 0);  // Reserved
        writeInt2(buffer, offset + 10, 32);  // DataOffset
        writeInt4(buffer, offset + 12, 32);  // DataLength
        
        // Name
        System.arraycopy(getName().getBytes(), 0, buffer, offset + 16, nameLen);
        
        // Data
        int dataOffset = offset + 16 + nameLen;
        dataOffset = (dataOffset + 7) & ~7;  // 8-byte alignment
        
        writeInt8(buffer, dataOffset, timeout);  // Timeout
        writeInt4(buffer, dataOffset + 8, flags);  // Flags
        writeInt8(buffer, dataOffset + 12, 0);  // Reserved
        System.arraycopy(createGuid.toBytes(), 0, buffer, dataOffset + 20, 16);  // CreateGuid
    }
}
```

### 4.4 Durable Handle Reconnect Context
```java
package jcifs.internal.smb2.persistent;

public class DurableHandleReconnect extends Smb2CreateContext {
    public static final String NAME = "DHnC";  // Durable Handle Reconnect
    
    private byte[] fileId;  // 16-byte file ID from previous open
    
    public DurableHandleReconnect(byte[] fileId) {
        super(NAME);
        if (fileId.length != 16) {
            throw new IllegalArgumentException("File ID must be 16 bytes");
        }
        this.fileId = Arrays.copyOf(fileId, 16);
    }
    
    @Override
    public void encode(byte[] buffer, int offset) {
        // Context header
        int nameLen = getName().length();
        writeInt4(buffer, offset, 16);  // Next
        writeInt2(buffer, offset + 4, nameLen);  // NameOffset
        writeInt2(buffer, offset + 6, nameLen);  // NameLength
        writeInt2(buffer, offset + 8, 0);  // Reserved
        writeInt2(buffer, offset + 10, 16);  // DataOffset
        writeInt4(buffer, offset + 12, 16);  // DataLength
        
        // Name
        System.arraycopy(getName().getBytes(), 0, buffer, offset + 16, nameLen);
        
        // Data (16-byte file ID)
        int dataOffset = offset + 16 + nameLen;
        dataOffset = (dataOffset + 7) & ~7;  // 8-byte alignment
        System.arraycopy(fileId, 0, buffer, dataOffset, 16);
    }
}
```

### 4.5 Persistent Handle Manager
```java
package jcifs.internal.smb2.persistent;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.io.*;
import java.nio.file.*;

public class PersistentHandleManager {
    private final ConcurrentHashMap<String, HandleInfo> handles;
    private final ConcurrentHashMap<HandleGuid, HandleInfo> guidToHandle;
    private final Path stateDirectory;
    private final ScheduledExecutorService scheduler;
    private final CIFSContext context;
    
    public PersistentHandleManager(CIFSContext context) {
        this.context = context;
        this.handles = new ConcurrentHashMap<>();
        this.guidToHandle = new ConcurrentHashMap<>();
        this.scheduler = Executors.newScheduledThreadPool(1);
        
        // Create state directory for persistent storage
        String homeDir = System.getProperty("user.home");
        this.stateDirectory = Paths.get(homeDir, ".jcifs", "handles");
        try {
            Files.createDirectories(stateDirectory);
        } catch (IOException e) {
            log.error("Failed to create handle state directory", e);
        }
        
        // Load persisted handles on startup
        loadPersistedHandles();
        
        // Schedule periodic persistence
        scheduler.scheduleAtFixedRate(this::persistHandles, 30, 30, TimeUnit.SECONDS);
    }
    
    public static class HandleInfo implements Serializable {
        private static final long serialVersionUID = 1L;
        
        private final String path;
        private final HandleGuid createGuid;
        private final byte[] fileId;
        private final HandleType type;
        private final long timeout;
        private final long createTime;
        private volatile long lastAccessTime;
        private final Smb2LeaseKey leaseKey;  // Associated lease if any
        private volatile boolean reconnecting;
        private transient SmbFile file;  // Not serialized
        
        public HandleInfo(String path, HandleGuid guid, byte[] fileId, 
                         HandleType type, long timeout, Smb2LeaseKey leaseKey) {
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
        
        public boolean isExpired() {
            if (type == HandleType.PERSISTENT) {
                return false;  // Persistent handles don't expire
            }
            long elapsed = System.currentTimeMillis() - lastAccessTime;
            return elapsed > timeout;
        }
        
        public void updateAccessTime() {
            this.lastAccessTime = System.currentTimeMillis();
        }
    }
    
    public HandleGuid requestDurableHandle(String path, HandleType type, 
                                          long timeout, Smb2LeaseKey leaseKey) {
        HandleGuid guid = new HandleGuid();
        
        // Will be populated after successful create response
        HandleInfo info = new HandleInfo(path, guid, new byte[16], type, timeout, leaseKey);
        
        handles.put(path, info);
        guidToHandle.put(guid, info);
        
        if (type == HandleType.PERSISTENT) {
            persistHandle(info);
        }
        
        return guid;
    }
    
    public void updateHandleFileId(HandleGuid guid, byte[] fileId) {
        HandleInfo info = guidToHandle.get(guid);
        if (info != null) {
            System.arraycopy(fileId, 0, info.fileId, 0, 16);
            if (info.type == HandleType.PERSISTENT) {
                persistHandle(info);
            }
        }
    }
    
    public HandleInfo getHandleForReconnect(String path) {
        HandleInfo info = handles.get(path);
        if (info != null && !info.isExpired()) {
            info.reconnecting = true;
            return info;
        }
        return null;
    }
    
    public void completeReconnect(String path, boolean success) {
        HandleInfo info = handles.get(path);
        if (info != null) {
            if (success) {
                info.updateAccessTime();
                info.reconnecting = false;
            } else {
                // Remove failed handle
                handles.remove(path);
                guidToHandle.remove(info.createGuid);
                removePersistedHandle(info);
            }
        }
    }
    
    public void releaseHandle(String path) {
        HandleInfo info = handles.remove(path);
        if (info != null) {
            guidToHandle.remove(info.createGuid);
            removePersistedHandle(info);
        }
    }
    
    private void persistHandles() {
        for (HandleInfo info : handles.values()) {
            if (info.type == HandleType.PERSISTENT && !info.reconnecting) {
                persistHandle(info);
            }
        }
    }
    
    private void persistHandle(HandleInfo info) {
        Path handleFile = stateDirectory.resolve(info.createGuid.toString() + ".handle");
        try (ObjectOutputStream oos = new ObjectOutputStream(
                Files.newOutputStream(handleFile))) {
            oos.writeObject(info);
        } catch (IOException e) {
            log.error("Failed to persist handle: " + info.path, e);
        }
    }
    
    private void removePersistedHandle(HandleInfo info) {
        if (info.type != HandleType.PERSISTENT) {
            return;
        }
        
        Path handleFile = stateDirectory.resolve(info.createGuid.toString() + ".handle");
        try {
            Files.deleteIfExists(handleFile);
        } catch (IOException e) {
            log.error("Failed to remove persisted handle", e);
        }
    }
    
    private void loadPersistedHandles() {
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(
                stateDirectory, "*.handle")) {
            for (Path handleFile : stream) {
                try (ObjectInputStream ois = new ObjectInputStream(
                        Files.newInputStream(handleFile))) {
                    HandleInfo info = (HandleInfo) ois.readObject();
                    
                    // Only load if not expired
                    if (!info.isExpired()) {
                        handles.put(info.path, info);
                        guidToHandle.put(info.createGuid, info);
                    } else {
                        Files.delete(handleFile);
                    }
                } catch (Exception e) {
                    log.error("Failed to load handle file: " + handleFile, e);
                    Files.deleteIfExists(handleFile);
                }
            }
        } catch (IOException e) {
            log.error("Failed to load persisted handles", e);
        }
    }
    
    public void shutdown() {
        scheduler.shutdown();
        persistHandles();  // Final persist before shutdown
    }
}
```

## 5. Handle Reconnection Logic

### 5.1 Automatic Reconnection Handler
```java
package jcifs.internal.smb2.persistent;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public class HandleReconnector {
    private final PersistentHandleManager handleManager;
    private final int maxRetries;
    private final long retryDelay;
    
    public HandleReconnector(PersistentHandleManager manager) {
        this.handleManager = manager;
        this.maxRetries = 3;
        this.retryDelay = 1000;  // 1 second
    }
    
    public CompletableFuture<SmbFile> reconnectHandle(SmbFile file, Exception cause) {
        String path = file.getPath();
        HandleInfo info = handleManager.getHandleForReconnect(path);
        
        if (info == null) {
            return CompletableFuture.failedFuture(
                new IOException("No durable handle available for reconnection"));
        }
        
        return attemptReconnect(file, info, 0);
    }
    
    private CompletableFuture<SmbFile> attemptReconnect(SmbFile file, 
                                                        HandleInfo info, 
                                                        int attempt) {
        if (attempt >= maxRetries) {
            handleManager.completeReconnect(info.path, false);
            return CompletableFuture.failedFuture(
                new IOException("Failed to reconnect after " + maxRetries + " attempts"));
        }
        
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Wait before retry (except first attempt)
                if (attempt > 0) {
                    Thread.sleep(retryDelay * attempt);
                }
                
                // Create reconnect context
                DurableHandleReconnect reconnectCtx = 
                    new DurableHandleReconnect(info.fileId);
                
                // Attempt to reopen with reconnect context
                Smb2CreateRequest createReq = new Smb2CreateRequest();
                createReq.setPath(info.path);
                createReq.addCreateContext(reconnectCtx);
                
                // Add lease context if associated
                if (info.leaseKey != null) {
                    createReq.addLeaseContext(info.leaseKey, 
                        Smb2LeaseState.SMB2_LEASE_NONE, false);
                }
                
                // Send create request
                Smb2CreateResponse response = (Smb2CreateResponse) 
                    file.getTree().send(createReq);
                
                if (response.isSuccess()) {
                    // Update file with new handle
                    file.setFileId(response.getFileId());
                    handleManager.completeReconnect(info.path, true);
                    return file;
                } else {
                    throw new IOException("Reconnect failed: " + response.getStatus());
                }
                
            } catch (Exception e) {
                log.debug("Reconnect attempt {} failed: {}", attempt + 1, e.getMessage());
                
                // Retry
                return attemptReconnect(file, info, attempt + 1).join();
            }
        });
    }
}
```

## 6. Integration with Existing Code

### 6.1 Modifying Smb2CreateRequest
```java
// In Smb2CreateRequest.java
public void addDurableHandleContext(HandleType type, long timeout, HandleGuid guid) {
    switch (type) {
        case DURABLE_V1:
            addCreateContext(new DurableHandleRequest());
            break;
            
        case DURABLE_V2:
            addCreateContext(new DurableHandleV2Request(timeout, false));
            break;
            
        case PERSISTENT:
            addCreateContext(new DurableHandleV2Request(0, true));
            break;
    }
}

public void addReconnectContext(byte[] fileId) {
    addCreateContext(new DurableHandleReconnect(fileId));
}
```

### 6.2 Modifying SmbFile
```java
// In SmbFile.java
private PersistentHandleManager handleManager;
private HandleGuid handleGuid;
private HandleType handleType;
private boolean durableHandleRequested;

protected void doConnect() throws IOException {
    // Check for existing durable handle
    handleManager = tree.getSession().getHandleManager();
    HandleInfo existingHandle = handleManager.getHandleForReconnect(getPath());
    
    if (existingHandle != null) {
        // Attempt reconnection
        try {
            reconnectWithDurableHandle(existingHandle);
            return;  // Success
        } catch (IOException e) {
            log.debug("Durable handle reconnect failed, opening new handle", e);
        }
    }
    
    // Request new durable handle if configured
    if (context.getConfig().isUseDurableHandles()) {
        requestDurableHandle();
    }
    
    // ... rest of normal connection logic ...
}

private void requestDurableHandle() {
    Configuration config = context.getConfig();
    
    // Determine handle type based on configuration and server capabilities
    if (tree.getSession().supports(SMB3_0) && config.isUsePersistentHandles()) {
        handleType = HandleType.PERSISTENT;
    } else if (tree.getSession().supports(SMB3_0)) {
        handleType = HandleType.DURABLE_V2;
    } else if (tree.getSession().supports(SMB2_1)) {
        handleType = HandleType.DURABLE_V1;
    } else {
        return;  // No durable handle support
    }
    
    long timeout = config.getDurableHandleTimeout();
    Smb2LeaseKey leaseKey = getLeaseKey();  // Get associated lease if any
    
    handleGuid = handleManager.requestDurableHandle(getPath(), handleType, 
                                                    timeout, leaseKey);
    durableHandleRequested = true;
    
    // Add to create request
    if (createRequest != null) {
        createRequest.addDurableHandleContext(handleType, timeout, handleGuid);
    }
}

private void reconnectWithDurableHandle(HandleInfo handle) throws IOException {
    Smb2CreateRequest request = new Smb2CreateRequest();
    request.setPath(handle.path);
    request.addReconnectContext(handle.fileId);
    
    // Add lease context if needed
    if (handle.leaseKey != null) {
        request.addLeaseContext(handle.leaseKey, Smb2LeaseState.SMB2_LEASE_NONE, false);
    }
    
    Smb2CreateResponse response = (Smb2CreateResponse) tree.send(request);
    
    if (response.isSuccess()) {
        this.fileId = response.getFileId();
        this.handleGuid = handle.createGuid;
        this.handleType = handle.type;
        handleManager.completeReconnect(handle.path, true);
    } else {
        handleManager.completeReconnect(handle.path, false);
        throw new IOException("Failed to reconnect durable handle");
    }
}

@Override
public void close() throws IOException {
    try {
        // Normal close operations
        super.close();
    } finally {
        // Don't release durable handle on close if it's persistent
        if (handleManager != null && handleType != HandleType.PERSISTENT) {
            handleManager.releaseHandle(getPath());
        }
    }
}

// Handle network errors with automatic reconnection
@Override
protected void handleNetworkError(IOException e) {
    if (handleType != null && handleType != HandleType.NONE) {
        // Attempt automatic reconnection
        HandleReconnector reconnector = new HandleReconnector(handleManager);
        try {
            SmbFile reconnected = reconnector.reconnectHandle(this, e).get(5, TimeUnit.SECONDS);
            // Update this file's state from reconnected file
            this.fileId = reconnected.fileId;
        } catch (Exception reconnectError) {
            log.error("Failed to reconnect durable handle", reconnectError);
            throw new IOException("Connection lost and reconnection failed", e);
        }
    } else {
        throw e;  // No durable handle, propagate error
    }
}
```

### 6.3 Session Integration
```java
// In SmbSession.java
private PersistentHandleManager handleManager;

public SmbSession(CIFSContext context, SmbTransport transport) {
    // ... existing initialization ...
    
    if (context.getConfig().isUseDurableHandles()) {
        this.handleManager = new PersistentHandleManager(context);
    }
}

public PersistentHandleManager getHandleManager() {
    return handleManager;
}

@Override
public void logoff() throws IOException {
    if (handleManager != null) {
        handleManager.shutdown();
    }
    // ... existing logoff logic ...
}
```

## 7. Configuration

### 7.1 Configuration Properties
```java
// In PropertyConfiguration.java
public static final String USE_DURABLE_HANDLES = "jcifs.smb.client.useDurableHandles";
public static final String USE_PERSISTENT_HANDLES = "jcifs.smb.client.usePersistentHandles";
public static final String DURABLE_HANDLE_TIMEOUT = "jcifs.smb.client.durableHandleTimeout";
public static final String HANDLE_RECONNECT_RETRIES = "jcifs.smb.client.handleReconnectRetries";
public static final String HANDLE_STATE_DIR = "jcifs.smb.client.handleStateDirectory";

public boolean isUseDurableHandles() {
    return getBooleanProperty(USE_DURABLE_HANDLES, true);
}

public boolean isUsePersistentHandles() {
    return getBooleanProperty(USE_PERSISTENT_HANDLES, false);
}

public long getDurableHandleTimeout() {
    return getLongProperty(DURABLE_HANDLE_TIMEOUT, 120000);  // 2 minutes
}

public int getHandleReconnectRetries() {
    return getIntProperty(HANDLE_RECONNECT_RETRIES, 3);
}

public String getHandleStateDirectory() {
    return getProperty(HANDLE_STATE_DIR, 
        System.getProperty("user.home") + "/.jcifs/handles");
}
```

## 8. Testing Strategy

### 8.1 Unit Tests
```java
package jcifs.tests.smb3;

import org.junit.Test;
import static org.junit.Assert.*;

public class PersistentHandleTest {
    
    @Test
    public void testHandleGuidGeneration() {
        HandleGuid guid1 = new HandleGuid();
        HandleGuid guid2 = new HandleGuid();
        
        assertNotEquals(guid1, guid2);
        assertEquals(16, guid1.toBytes().length);
        
        // Test round-trip
        HandleGuid guid3 = new HandleGuid(guid1.toBytes());
        assertEquals(guid1, guid3);
    }
    
    @Test
    public void testHandleInfoExpiration() {
        HandleInfo info = new HandleInfo(
            "/test/file.txt",
            new HandleGuid(),
            new byte[16],
            HandleType.DURABLE_V2,
            1000,  // 1 second timeout
            null
        );
        
        assertFalse(info.isExpired());
        
        // Wait for expiration
        Thread.sleep(1500);
        assertTrue(info.isExpired());
        
        // Persistent handles don't expire
        HandleInfo persistent = new HandleInfo(
            "/test/file2.txt",
            new HandleGuid(),
            new byte[16],
            HandleType.PERSISTENT,
            0,
            null
        );
        
        Thread.sleep(100);
        assertFalse(persistent.isExpired());
    }
    
    @Test
    public void testHandleManagerPersistence() throws Exception {
        CIFSContext context = new BaseContext(new PropertyConfiguration());
        PersistentHandleManager manager = new PersistentHandleManager(context);
        
        // Create persistent handle
        HandleGuid guid = manager.requestDurableHandle(
            "/test/file.txt",
            HandleType.PERSISTENT,
            0,
            null
        );
        
        byte[] fileId = new byte[16];
        Arrays.fill(fileId, (byte)0x42);
        manager.updateHandleFileId(guid, fileId);
        
        // Shutdown and recreate manager
        manager.shutdown();
        
        PersistentHandleManager manager2 = new PersistentHandleManager(context);
        HandleInfo recovered = manager2.getHandleForReconnect("/test/file.txt");
        
        assertNotNull(recovered);
        assertEquals(HandleType.PERSISTENT, recovered.type);
        assertArrayEquals(fileId, recovered.fileId);
    }
}
```

### 8.2 Integration Tests
```java
@Test
public void testDurableHandleReconnection() throws Exception {
    CIFSContext context = getTestContext();
    context.getConfig().setProperty("jcifs.smb.client.useDurableHandles", "true");
    
    SmbFile file = new SmbFile("smb://server/share/test.txt", context);
    file.createNewFile();
    
    // Write some data
    try (OutputStream os = file.getOutputStream()) {
        os.write("test data".getBytes());
    }
    
    // Simulate network disconnection
    file.getTree().getSession().getTransport().disconnect();
    
    // Try to read - should trigger reconnection
    try (InputStream is = file.getInputStream()) {
        byte[] buffer = new byte[9];
        is.read(buffer);
        assertEquals("test data", new String(buffer));
    }
}

@Test
public void testPersistentHandleSurvivesReboot() throws Exception {
    // This test requires special setup with server reboot capability
    CIFSContext context = getTestContext();
    context.getConfig().setProperty("jcifs.smb.client.usePersistentHandles", "true");
    
    SmbFile file = new SmbFile("smb://server/share/persistent.txt", context);
    file.createNewFile();
    
    // Get handle info
    PersistentHandleManager manager = file.getTree().getSession().getHandleManager();
    HandleInfo handle = manager.getHandleForReconnect(file.getPath());
    assertNotNull(handle);
    assertEquals(HandleType.PERSISTENT, handle.type);
    
    // Simulate server reboot
    // ... server reboot logic ...
    
    // Reconnect should succeed
    SmbFile file2 = new SmbFile("smb://server/share/persistent.txt", context);
    assertTrue(file2.exists());  // Should reconnect with persistent handle
}
```

## 9. Error Handling and Recovery

### 9.1 Handle Break Scenarios
```java
public enum HandleBreakReason {
    NETWORK_FAILURE,      // Network connection lost
    SESSION_EXPIRED,      // Session timeout
    SERVER_REBOOT,        // Server restart
    HANDLE_EXPIRED,       // Handle timeout reached
    LEASE_BREAK,         // Associated lease broken
    EXPLICIT_CLOSE       // User closed handle
}

public class HandleBreakHandler {
    public void handleBreak(HandleInfo handle, HandleBreakReason reason) {
        switch (reason) {
            case NETWORK_FAILURE:
            case SESSION_EXPIRED:
                // Attempt immediate reconnection
                scheduleReconnect(handle, 0);
                break;
                
            case SERVER_REBOOT:
                // Wait before reconnecting
                scheduleReconnect(handle, 5000);
                break;
                
            case HANDLE_EXPIRED:
            case LEASE_BREAK:
                // Release handle, create new one
                releaseAndRecreate(handle);
                break;
                
            case EXPLICIT_CLOSE:
                // Clean release
                releaseHandle(handle);
                break;
        }
    }
}
```

## 10. Performance Considerations

### 10.1 Handle Caching Strategy
```java
public class HandleCache {
    private final int maxHandles = 1000;
    private final LinkedHashMap<String, HandleInfo> lruCache;
    
    public HandleCache() {
        this.lruCache = new LinkedHashMap<String, HandleInfo>(maxHandles, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, HandleInfo> eldest) {
                if (size() > maxHandles) {
                    // Release least recently used non-persistent handle
                    if (eldest.getValue().type != HandleType.PERSISTENT) {
                        releaseHandle(eldest.getValue());
                        return true;
                    }
                }
                return false;
            }
        };
    }
}
```

### 10.2 Batch Handle Operations
```java
public class BatchHandleOperations {
    public void reconnectMultipleHandles(List<HandleInfo> handles) {
        List<CompletableFuture<Void>> futures = new ArrayList<>();
        
        for (HandleInfo handle : handles) {
            futures.add(CompletableFuture.runAsync(() -> {
                try {
                    reconnectHandle(handle);
                } catch (Exception e) {
                    log.error("Failed to reconnect handle: " + handle.path, e);
                }
            }));
        }
        
        // Wait for all reconnections
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
    }
}
```

## 11. Monitoring and Metrics

### 11.1 Handle Statistics
```java
public class HandleStatistics {
    private final AtomicLong handlesRequested = new AtomicLong();
    private final AtomicLong handlesGranted = new AtomicLong();
    private final AtomicLong reconnectAttempts = new AtomicLong();
    private final AtomicLong reconnectSuccesses = new AtomicLong();
    private final AtomicLong handleExpirations = new AtomicLong();
    
    public double getReconnectSuccessRate() {
        long attempts = reconnectAttempts.get();
        if (attempts == 0) return 0.0;
        return (double) reconnectSuccesses.get() / attempts;
    }
}
```

## 12. Security Considerations

### 12.1 Handle State Encryption
```java
public class SecureHandleStorage {
    private final SecretKey encryptionKey;
    
    public void saveEncrypted(HandleInfo handle, Path file) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (CipherOutputStream cos = new CipherOutputStream(baos, cipher);
             ObjectOutputStream oos = new ObjectOutputStream(cos)) {
            oos.writeObject(handle);
        }
        
        Files.write(file, baos.toByteArray());
    }
}
```