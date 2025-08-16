# SMB3 Lease Feature - Detailed Design Document

## 1. Overview

SMB3 leases provide a client caching mechanism that replaces the traditional oplock mechanism. Leases enable better performance through client-side caching while maintaining cache coherency across multiple clients.

## 2. Protocol Specification Reference

- **MS-SMB2 Section 2.2.13**: SMB2 CREATE Request with Lease Context
- **MS-SMB2 Section 2.2.14**: SMB2 CREATE Response with Lease State
- **MS-SMB2 Section 2.2.23**: SMB2 LEASE_BREAK Notification
- **MS-SMB2 Section 2.2.24**: SMB2 LEASE_BREAK Acknowledgment

## 3. Lease Types and States

### 3.1 Lease State Flags
```java
public class Smb2LeaseState {
    // Lease state flags (can be combined)
    public static final int SMB2_LEASE_NONE           = 0x00;
    public static final int SMB2_LEASE_READ_CACHING   = 0x01;  // R - Read caching
    public static final int SMB2_LEASE_HANDLE_CACHING = 0x02;  // H - Handle caching  
    public static final int SMB2_LEASE_WRITE_CACHING  = 0x04;  // W - Write caching
    
    // Common combinations
    public static final int SMB2_LEASE_READ_HANDLE    = 0x03;  // RH
    public static final int SMB2_LEASE_READ_WRITE     = 0x05;  // RW
    public static final int SMB2_LEASE_FULL           = 0x07;  // RWH
}
```

### 3.2 Lease Versions
- **Lease V1**: Basic lease support (SMB 3.0)
- **Lease V2**: Adds epoch support for better consistency (SMB 3.0.2+)

## 4. Data Structures

### 4.1 Lease Key Structure
```java
package jcifs.internal.smb2.lease;

import java.security.SecureRandom;
import java.util.Arrays;

public class Smb2LeaseKey {
    private final byte[] key;  // 16-byte lease key
    private static final SecureRandom random = new SecureRandom();
    
    public Smb2LeaseKey() {
        this.key = new byte[16];
        random.nextBytes(this.key);
    }
    
    public Smb2LeaseKey(byte[] key) {
        if (key.length != 16) {
            throw new IllegalArgumentException("Lease key must be 16 bytes");
        }
        this.key = Arrays.copyOf(key, 16);
    }
    
    public byte[] getKey() {
        return Arrays.copyOf(key, 16);
    }
    
    @Override
    public boolean equals(Object obj) {
        if (obj instanceof Smb2LeaseKey) {
            return Arrays.equals(key, ((Smb2LeaseKey)obj).key);
        }
        return false;
    }
    
    @Override
    public int hashCode() {
        return Arrays.hashCode(key);
    }
}
```

### 4.2 Lease Context Structure
```java
package jcifs.internal.smb2.lease;

import jcifs.internal.smb2.create.Smb2CreateContext;

public class Smb2LeaseContext extends Smb2CreateContext {
    // Context name for lease request
    public static final String NAME_REQUEST = "RqLs";
    public static final String NAME_RESPONSE = "RqLs";
    
    private Smb2LeaseKey leaseKey;
    private int leaseState;
    private int leaseFlags;
    private long leaseDuration;  // For V2
    private Smb2LeaseKey parentLeaseKey;  // For V2
    private int epoch;  // For V2
    
    // Wire format structure
    // Lease V1: 32 bytes
    // Lease V2: 52 bytes
    
    @Override
    public void encode(byte[] buffer, int offset) {
        // Write context header
        writeInt4(buffer, offset, getName().length());  // NameOffset
        writeInt4(buffer, offset + 4, getName().length());  // NameLength
        writeInt4(buffer, offset + 8, 16);  // Reserved
        
        int dataOffset = offset + 16 + getName().length();
        dataOffset = (dataOffset + 7) & ~7;  // 8-byte alignment
        
        writeInt4(buffer, offset + 12, dataOffset - offset);  // DataOffset
        
        // Write context name
        System.arraycopy(getName().getBytes(), 0, buffer, offset + 16, getName().length());
        
        // Write lease data
        System.arraycopy(leaseKey.getKey(), 0, buffer, dataOffset, 16);  // LeaseKey
        writeInt4(buffer, dataOffset + 16, leaseState);  // LeaseState
        writeInt4(buffer, dataOffset + 20, leaseFlags);  // LeaseFlags
        writeInt8(buffer, dataOffset + 24, leaseDuration);  // LeaseDuration
        
        if (isV2()) {
            System.arraycopy(parentLeaseKey.getKey(), 0, buffer, dataOffset + 32, 16);  // ParentLeaseKey
            writeInt2(buffer, dataOffset + 48, epoch);  // Epoch
            writeInt2(buffer, dataOffset + 50, 0);  // Reserved
        }
    }
    
    @Override
    public void decode(byte[] buffer, int offset, int length) {
        // Decode lease response
        byte[] keyBytes = new byte[16];
        System.arraycopy(buffer, offset, keyBytes, 0, 16);
        this.leaseKey = new Smb2LeaseKey(keyBytes);
        
        this.leaseState = readInt4(buffer, offset + 16);
        this.leaseFlags = readInt4(buffer, offset + 20);
        this.leaseDuration = readInt8(buffer, offset + 24);
        
        if (length >= 52) {  // V2 lease
            byte[] parentKeyBytes = new byte[16];
            System.arraycopy(buffer, offset + 32, parentKeyBytes, 0, 16);
            this.parentLeaseKey = new Smb2LeaseKey(parentKeyBytes);
            this.epoch = readInt2(buffer, offset + 48);
        }
    }
    
    public boolean isV2() {
        return parentLeaseKey != null;
    }
}
```

### 4.3 Lease Manager
```java
package jcifs.internal.smb2.lease;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import jcifs.CIFSContext;

public class LeaseManager {
    private final ConcurrentHashMap<Smb2LeaseKey, LeaseEntry> leases;
    private final ConcurrentHashMap<String, Smb2LeaseKey> pathToLease;
    private final ReadWriteLock lock;
    private final CIFSContext context;
    
    public LeaseManager(CIFSContext context) {
        this.context = context;
        this.leases = new ConcurrentHashMap<>();
        this.pathToLease = new ConcurrentHashMap<>();
        this.lock = new ReentrantReadWriteLock();
    }
    
    public static class LeaseEntry {
        private final Smb2LeaseKey leaseKey;
        private volatile int leaseState;
        private volatile int epoch;
        private final long createTime;
        private volatile long lastAccessTime;
        private final String path;
        private volatile boolean breaking;
        
        public LeaseEntry(Smb2LeaseKey key, String path, int state) {
            this.leaseKey = key;
            this.path = path;
            this.leaseState = state;
            this.createTime = System.currentTimeMillis();
            this.lastAccessTime = createTime;
            this.epoch = 1;
            this.breaking = false;
        }
        
        public synchronized void updateState(int newState) {
            this.leaseState = newState;
            this.lastAccessTime = System.currentTimeMillis();
        }
        
        public synchronized void incrementEpoch() {
            this.epoch++;
        }
        
        public boolean hasReadCache() {
            return (leaseState & Smb2LeaseState.SMB2_LEASE_READ_CACHING) != 0;
        }
        
        public boolean hasWriteCache() {
            return (leaseState & Smb2LeaseState.SMB2_LEASE_WRITE_CACHING) != 0;
        }
        
        public boolean hasHandleCache() {
            return (leaseState & Smb2LeaseState.SMB2_LEASE_HANDLE_CACHING) != 0;
        }
    }
    
    public Smb2LeaseKey requestLease(String path, int requestedState) {
        lock.writeLock().lock();
        try {
            // Check if we already have a lease for this path
            Smb2LeaseKey existingKey = pathToLease.get(path);
            if (existingKey != null) {
                LeaseEntry entry = leases.get(existingKey);
                if (entry != null && !entry.breaking) {
                    entry.lastAccessTime = System.currentTimeMillis();
                    return existingKey;
                }
            }
            
            // Create new lease
            Smb2LeaseKey newKey = new Smb2LeaseKey();
            LeaseEntry newEntry = new LeaseEntry(newKey, path, requestedState);
            leases.put(newKey, newEntry);
            pathToLease.put(path, newKey);
            
            return newKey;
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    public void updateLease(Smb2LeaseKey key, int grantedState) {
        LeaseEntry entry = leases.get(key);
        if (entry != null) {
            entry.updateState(grantedState);
        }
    }
    
    public LeaseEntry getLease(Smb2LeaseKey key) {
        return leases.get(key);
    }
    
    public void handleLeaseBreak(Smb2LeaseKey key, int newState) {
        LeaseEntry entry = leases.get(key);
        if (entry != null) {
            entry.breaking = true;
            entry.updateState(newState);
            // Flush any cached data if losing write cache
            if (!entry.hasWriteCache()) {
                flushCachedWrites(entry.path);
            }
            // Invalidate cached data if losing read cache
            if (!entry.hasReadCache()) {
                invalidateReadCache(entry.path);
            }
            entry.breaking = false;
        }
    }
    
    public void releaseLease(Smb2LeaseKey key) {
        lock.writeLock().lock();
        try {
            LeaseEntry entry = leases.remove(key);
            if (entry != null) {
                pathToLease.remove(entry.path);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    private void flushCachedWrites(String path) {
        // Implementation to flush cached writes
        // This will be called when losing write cache
    }
    
    private void invalidateReadCache(String path) {
        // Implementation to invalidate read cache
        // This will be called when losing read cache
    }
}
```

## 5. Lease Break Handling

### 5.1 Lease Break Notification
```java
package jcifs.internal.smb2.lease;

import jcifs.internal.smb2.ServerMessageBlock2;

public class Smb2LeaseBreakNotification extends ServerMessageBlock2 {
    // Command code for lease break
    public static final int SMB2_OPLOCK_BREAK = 0x0012;
    
    private int structureSize;
    private int flags;
    private Smb2LeaseKey leaseKey;
    private int currentLeaseState;
    private int newLeaseState;
    private int breakReason;
    private int accessMaskHint;
    private int shareAccessHint;
    
    @Override
    protected int writePayload(byte[] dst, int dstIndex) {
        int start = dstIndex;
        
        // StructureSize (2 bytes) - must be 44
        writeInt2(dst, dstIndex, 44);
        dstIndex += 2;
        
        // Reserved (2 bytes)
        writeInt2(dst, dstIndex, 0);
        dstIndex += 2;
        
        // Flags (4 bytes)
        writeInt4(dst, dstIndex, flags);
        dstIndex += 4;
        
        // LeaseKey (16 bytes)
        System.arraycopy(leaseKey.getKey(), 0, dst, dstIndex, 16);
        dstIndex += 16;
        
        // CurrentLeaseState (4 bytes)
        writeInt4(dst, dstIndex, currentLeaseState);
        dstIndex += 4;
        
        // NewLeaseState (4 bytes)
        writeInt4(dst, dstIndex, newLeaseState);
        dstIndex += 4;
        
        // BreakReason (4 bytes)
        writeInt4(dst, dstIndex, breakReason);
        dstIndex += 4;
        
        // AccessMaskHint (4 bytes)
        writeInt4(dst, dstIndex, accessMaskHint);
        dstIndex += 4;
        
        // ShareAccessHint (4 bytes)
        writeInt4(dst, dstIndex, shareAccessHint);
        dstIndex += 4;
        
        return dstIndex - start;
    }
    
    @Override
    protected int readPayload(byte[] buffer, int offset) throws SMBProtocolDecodingException {
        int start = offset;
        
        // StructureSize (2 bytes)
        structureSize = readInt2(buffer, offset);
        offset += 2;
        
        // Reserved (2 bytes)
        offset += 2;
        
        // Flags (4 bytes)
        flags = readInt4(buffer, offset);
        offset += 4;
        
        // LeaseKey (16 bytes)
        byte[] keyBytes = new byte[16];
        System.arraycopy(buffer, offset, keyBytes, 0, 16);
        leaseKey = new Smb2LeaseKey(keyBytes);
        offset += 16;
        
        // CurrentLeaseState (4 bytes)
        currentLeaseState = readInt4(buffer, offset);
        offset += 4;
        
        // NewLeaseState (4 bytes)
        newLeaseState = readInt4(buffer, offset);
        offset += 4;
        
        // BreakReason (4 bytes)
        breakReason = readInt4(buffer, offset);
        offset += 4;
        
        // AccessMaskHint (4 bytes)
        accessMaskHint = readInt4(buffer, offset);
        offset += 4;
        
        // ShareAccessHint (4 bytes)
        shareAccessHint = readInt4(buffer, offset);
        offset += 4;
        
        return offset - start;
    }
}
```

### 5.2 Lease Break Acknowledgment
```java
package jcifs.internal.smb2.lease;

public class Smb2LeaseBreakAcknowledgment extends ServerMessageBlock2 {
    private int structureSize = 36;
    private int reserved;
    private int flags;
    private Smb2LeaseKey leaseKey;
    private int leaseState;
    private long leaseDuration;
    
    public Smb2LeaseBreakAcknowledgment(Smb2LeaseKey key, int state) {
        this.leaseKey = key;
        this.leaseState = state;
        this.leaseDuration = 0;  // Not used in acknowledgment
    }
    
    @Override
    protected int writePayload(byte[] dst, int dstIndex) {
        int start = dstIndex;
        
        // StructureSize (2 bytes) - must be 36
        writeInt2(dst, dstIndex, 36);
        dstIndex += 2;
        
        // Reserved (2 bytes)
        writeInt2(dst, dstIndex, 0);
        dstIndex += 2;
        
        // Flags (4 bytes)
        writeInt4(dst, dstIndex, flags);
        dstIndex += 4;
        
        // LeaseKey (16 bytes)
        System.arraycopy(leaseKey.getKey(), 0, dst, dstIndex, 16);
        dstIndex += 16;
        
        // LeaseState (4 bytes)
        writeInt4(dst, dstIndex, leaseState);
        dstIndex += 4;
        
        // LeaseDuration (8 bytes)
        writeInt8(dst, dstIndex, leaseDuration);
        dstIndex += 8;
        
        return dstIndex - start;
    }
}
```

## 6. Integration with Existing Code

### 6.1 Modifying Smb2CreateRequest
```java
// In Smb2CreateRequest.java
public void addLeaseContext(Smb2LeaseKey key, int requestedState, boolean isV2) {
    Smb2LeaseContext leaseContext = new Smb2LeaseContext();
    leaseContext.setLeaseKey(key);
    leaseContext.setLeaseState(requestedState);
    if (isV2) {
        leaseContext.setEpoch(1);
        // Set parent lease key if available
    }
    addCreateContext(leaseContext);
}
```

### 6.2 Modifying SmbFile
```java
// In SmbFile.java
private Smb2LeaseKey leaseKey;
private int leaseState;
private LeaseManager leaseManager;

protected void doConnect() throws IOException {
    // ... existing connection logic ...
    
    if (context.getConfig().isUseLeases() && tree.getSession().supports(SMB3_0)) {
        // Request lease when opening file
        leaseManager = tree.getSession().getLeaseManager();
        int requestedState = isDirectory() ? 
            Smb2LeaseState.SMB2_LEASE_READ_HANDLE :
            Smb2LeaseState.SMB2_LEASE_FULL;
            
        leaseKey = leaseManager.requestLease(getPath(), requestedState);
        
        // Add lease context to create request
        if (createRequest != null) {
            createRequest.addLeaseContext(leaseKey, requestedState, 
                tree.getSession().supports(SMB3_0_2));
        }
    }
    
    // ... rest of connection logic ...
}

// Caching methods based on lease state
public boolean canCacheRead() {
    if (leaseKey != null) {
        LeaseEntry entry = leaseManager.getLease(leaseKey);
        return entry != null && entry.hasReadCache();
    }
    return false;  // Fall back to oplock logic
}

public boolean canCacheWrite() {
    if (leaseKey != null) {
        LeaseEntry entry = leaseManager.getLease(leaseKey);
        return entry != null && entry.hasWriteCache();
    }
    return false;
}

public boolean canCacheHandle() {
    if (leaseKey != null) {
        LeaseEntry entry = leaseManager.getLease(leaseKey);
        return entry != null && entry.hasHandleCache();
    }
    return false;
}
```

### 6.3 Transport Layer Integration
```java
// In SmbTransport.java
private void handleIncomingMessage(ServerMessageBlock2 msg) {
    if (msg instanceof Smb2LeaseBreakNotification) {
        Smb2LeaseBreakNotification breakNotif = (Smb2LeaseBreakNotification) msg;
        
        // Get lease manager from session
        LeaseManager leaseManager = session.getLeaseManager();
        
        // Handle the lease break
        leaseManager.handleLeaseBreak(
            breakNotif.getLeaseKey(),
            breakNotif.getNewLeaseState()
        );
        
        // Send acknowledgment
        Smb2LeaseBreakAcknowledgment ack = new Smb2LeaseBreakAcknowledgment(
            breakNotif.getLeaseKey(),
            breakNotif.getNewLeaseState()
        );
        
        sendAsync(ack);  // Send acknowledgment asynchronously
    }
    // ... handle other message types ...
}
```

## 7. Configuration

### 7.1 Configuration Properties
```java
// In PropertyConfiguration.java
public class PropertyConfiguration implements Configuration {
    // Lease configuration properties
    public static final String USE_LEASES = "jcifs.smb.client.useLeases";
    public static final String LEASE_TIMEOUT = "jcifs.smb.client.leaseTimeout";
    public static final String MAX_LEASES = "jcifs.smb.client.maxLeases";
    public static final String LEASE_VERSION = "jcifs.smb.client.leaseVersion";
    
    public boolean isUseLeases() {
        return getBooleanProperty(USE_LEASES, true);
    }
    
    public int getLeaseTimeout() {
        return getIntProperty(LEASE_TIMEOUT, 30000);  // 30 seconds default
    }
    
    public int getMaxLeases() {
        return getIntProperty(MAX_LEASES, 1000);  // Max concurrent leases
    }
    
    public int getLeaseVersion() {
        return getIntProperty(LEASE_VERSION, 2);  // Default to V2 if supported
    }
}
```

## 8. Testing Strategy

### 8.1 Unit Tests
```java
package jcifs.tests.smb3;

import org.junit.Test;
import static org.junit.Assert.*;

public class LeaseTest {
    
    @Test
    public void testLeaseKeyGeneration() {
        Smb2LeaseKey key1 = new Smb2LeaseKey();
        Smb2LeaseKey key2 = new Smb2LeaseKey();
        
        assertNotNull(key1.getKey());
        assertEquals(16, key1.getKey().length);
        assertFalse(Arrays.equals(key1.getKey(), key2.getKey()));
    }
    
    @Test
    public void testLeaseStateFlags() {
        int state = Smb2LeaseState.SMB2_LEASE_READ_WRITE;
        
        assertTrue((state & Smb2LeaseState.SMB2_LEASE_READ_CACHING) != 0);
        assertTrue((state & Smb2LeaseState.SMB2_LEASE_WRITE_CACHING) != 0);
        assertFalse((state & Smb2LeaseState.SMB2_LEASE_HANDLE_CACHING) != 0);
    }
    
    @Test
    public void testLeaseManager() {
        CIFSContext context = new BaseContext(new PropertyConfiguration());
        LeaseManager manager = new LeaseManager(context);
        
        String path = "/share/file.txt";
        int requestedState = Smb2LeaseState.SMB2_LEASE_FULL;
        
        Smb2LeaseKey key = manager.requestLease(path, requestedState);
        assertNotNull(key);
        
        LeaseEntry entry = manager.getLease(key);
        assertNotNull(entry);
        assertEquals(requestedState, entry.getLeaseState());
        
        // Test lease break
        manager.handleLeaseBreak(key, Smb2LeaseState.SMB2_LEASE_READ_CACHING);
        assertEquals(Smb2LeaseState.SMB2_LEASE_READ_CACHING, entry.getLeaseState());
    }
}
```

### 8.2 Integration Tests
```java
@Test
public void testLeaseWithRealServer() throws Exception {
    // Requires SMB3 capable server
    CIFSContext context = getTestContext();
    context.getConfig().setProperty("jcifs.smb.client.useLeases", "true");
    
    try (SmbFile file = new SmbFile("smb://server/share/test.txt", context)) {
        // Open file with lease
        file.createNewFile();
        
        // Verify lease was granted
        assertTrue(file.canCacheRead());
        
        // Write should be cached
        try (OutputStream os = file.getOutputStream()) {
            os.write("test data".getBytes());
        }
        
        // Verify caching behavior
        assertTrue(file.canCacheWrite());
    }
}
```

## 9. Performance Considerations

### 9.1 Memory Management
- Lease entries should be evicted based on LRU when max leases reached
- Implement periodic cleanup of expired leases

### 9.2 Thread Safety
- Use concurrent data structures for lease storage
- Minimize lock contention in hot paths
- Async handling of lease breaks

### 9.3 Network Efficiency
- Batch lease requests when possible
- Implement lease key reuse for related files
- Optimize lease break acknowledgment timing

## 10. Error Handling

### 10.1 Lease Break Timeout
```java
public void handleLeaseBreakWithTimeout(Smb2LeaseKey key, int newState) {
    CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
        handleLeaseBreak(key, newState);
    });
    
    try {
        future.get(5, TimeUnit.SECONDS);  // 5 second timeout
    } catch (TimeoutException e) {
        // Force lease release if break handling times out
        releaseLease(key);
        log.warn("Lease break timeout for key: {}", key);
    }
}
```

### 10.2 Fallback to Oplocks
```java
if (!context.getConfig().isUseLeases() || !session.supports(SMB3_0)) {
    // Fall back to traditional oplock mechanism
    useOplockInstead();
}
```

## 11. Monitoring and Metrics

### 11.1 Lease Statistics
```java
public class LeaseStatistics {
    private final AtomicLong leasesRequested = new AtomicLong();
    private final AtomicLong leasesGranted = new AtomicLong();
    private final AtomicLong leaseBreaks = new AtomicLong();
    private final AtomicLong leaseUpgrades = new AtomicLong();
    private final AtomicLong leaseDowngrades = new AtomicLong();
    
    // Getters and increment methods
}
```

## 12. Future Enhancements

1. **Directory Leases**: Extend lease support for directories
2. **Lease Key Persistence**: Save lease keys for reconnection
3. **Parent-Child Relationships**: Implement hierarchical leases
4. **Lease Sharing**: Support lease sharing across handles
5. **Performance Tuning**: Adaptive lease request strategies