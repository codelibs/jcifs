# RDMA (SMB Direct) Feature - Detailed Design Document

## 1. Overview

SMB Direct enables high-performance data transfer using Remote Direct Memory Access (RDMA) technology. This provides ultra-low latency and high bandwidth data transfer by bypassing the traditional TCP/IP stack and allowing direct memory-to-memory transfers between client and server.

## 2. Protocol Specification Reference

- **MS-SMBD**: SMB2 Remote Direct Memory Access (RDMA) Transport Protocol
- **MS-SMB2 Section 2.2.3.1.1**: SMB2 Negotiate Protocol Request with RDMA
- **MS-SMB2 Section 3.1.5.2**: RDMA Transport Connection
- **RFC 5040**: A Remote Direct Memory Access Protocol Specification
- **RFC 5041**: Direct Data Placement over Reliable Transports

## 3. RDMA Architecture

### 3.1 RDMA Capabilities
```java
public enum RdmaCapability {
    RDMA_READ,           // Remote direct read operations
    RDMA_WRITE,          // Remote direct write operations  
    RDMA_SEND_RECEIVE,   // Traditional send/receive with RDMA
    MEMORY_REGISTRATION, // Dynamic memory registration
    FAST_REGISTRATION   // Fast memory region registration
}

public class RdmaCapabilities {
    // RDMA transform capabilities
    public static final int SMB_DIRECT_RESPONSE_REQUESTED = 0x00000001;
    
    // Default RDMA settings
    public static final int DEFAULT_RDMA_READ_WRITE_SIZE = 1048576;  // 1MB
    public static final int DEFAULT_RECEIVE_CREDIT_MAX = 255;
    public static final int DEFAULT_SEND_CREDIT_TARGET = 32;
    public static final int DEFAULT_MAX_RECEIVE_SIZE = 8192;
    public static final int DEFAULT_MAX_FRAGMENTED_SIZE = 131072;    // 128KB
    public static final int DEFAULT_MAX_READ_WRITE_SIZE = 1048576;   // 1MB
}
```

### 3.2 RDMA Provider Interface
```java
package jcifs.internal.smb2.rdma;

public interface RdmaProvider {
    /**
     * Check if RDMA is available on this system
     */
    boolean isAvailable();
    
    /**
     * Get supported RDMA capabilities
     */
    Set<RdmaCapability> getSupportedCapabilities();
    
    /**
     * Create RDMA connection to remote endpoint
     */
    RdmaConnection createConnection(InetSocketAddress remote, 
                                   InetSocketAddress local) throws IOException;
    
    /**
     * Register memory region for RDMA operations
     */
    RdmaMemoryRegion registerMemory(ByteBuffer buffer, 
                                   EnumSet<RdmaAccess> access) throws IOException;
    
    /**
     * Get provider name (e.g., "InfiniBand", "iWARP", "RoCE")
     */
    String getProviderName();
    
    /**
     * Get maximum message size supported
     */
    int getMaxMessageSize();
    
    /**
     * Clean up provider resources
     */
    void shutdown();
}

public enum RdmaAccess {
    LOCAL_READ,
    LOCAL_WRITE,
    REMOTE_READ,
    REMOTE_WRITE,
    MEMORY_BIND
}
```

## 4. Data Structures

### 4.1 RDMA Connection
```java
package jcifs.internal.smb2.rdma;

import java.nio.ByteBuffer;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

public abstract class RdmaConnection implements AutoCloseable {
    protected final InetSocketAddress remoteAddress;
    protected final InetSocketAddress localAddress;
    protected final AtomicInteger sendCredits;
    protected final AtomicInteger receiveCredits;
    protected final BlockingQueue<RdmaWorkRequest> pendingRequests;
    
    // Connection state
    protected volatile RdmaConnectionState state;
    protected RdmaCredits credits;
    protected int maxFragmentedSize;
    protected int maxReadWriteSize;
    
    public enum RdmaConnectionState {
        DISCONNECTED,
        CONNECTING,
        CONNECTED,
        ESTABLISHED,
        ERROR,
        CLOSING,
        CLOSED
    }
    
    public RdmaConnection(InetSocketAddress remote, InetSocketAddress local) {
        this.remoteAddress = remote;
        this.localAddress = local;
        this.sendCredits = new AtomicInteger(0);
        this.receiveCredits = new AtomicInteger(RdmaCapabilities.DEFAULT_RECEIVE_CREDIT_MAX);
        this.pendingRequests = new LinkedBlockingQueue<>();
        this.state = RdmaConnectionState.DISCONNECTED;
        this.maxFragmentedSize = RdmaCapabilities.DEFAULT_MAX_FRAGMENTED_SIZE;
        this.maxReadWriteSize = RdmaCapabilities.DEFAULT_MAX_READ_WRITE_SIZE;
    }
    
    /**
     * Establish RDMA connection
     */
    public abstract void connect() throws IOException;
    
    /**
     * Send data using RDMA
     */
    public abstract void send(ByteBuffer data, RdmaMemoryRegion region) throws IOException;
    
    /**
     * Receive data using RDMA  
     */
    public abstract ByteBuffer receive(int timeout) throws IOException;
    
    /**
     * Perform RDMA read operation
     */
    public abstract void rdmaRead(RdmaMemoryRegion localRegion, 
                                 long remoteAddress, 
                                 int remoteKey,
                                 int length) throws IOException;
    
    /**
     * Perform RDMA write operation
     */
    public abstract void rdmaWrite(RdmaMemoryRegion localRegion,
                                  long remoteAddress,
                                  int remoteKey,
                                  int length) throws IOException;
    
    /**
     * Negotiate RDMA parameters
     */
    public abstract RdmaNegotiateResponse negotiate(RdmaNegotiateRequest request) throws IOException;
    
    public boolean canSend() {
        return sendCredits.get() > 0 && state == RdmaConnectionState.ESTABLISHED;
    }
    
    public void consumeSendCredit() {
        sendCredits.decrementAndGet();
    }
    
    public void grantSendCredit() {
        sendCredits.incrementAndGet();
    }
    
    public void grantReceiveCredit() {
        receiveCredits.incrementAndGet();
    }
    
    public int getAvailableSendCredits() {
        return sendCredits.get();
    }
    
    public int getAvailableReceiveCredits() {
        return receiveCredits.get();
    }
}
```

### 4.2 RDMA Memory Region
```java
package jcifs.internal.smb2.rdma;

public abstract class RdmaMemoryRegion implements AutoCloseable {
    protected final ByteBuffer buffer;
    protected final EnumSet<RdmaAccess> accessFlags;
    protected final int localKey;
    protected final int remoteKey;
    protected final long address;
    protected volatile boolean valid;
    
    public RdmaMemoryRegion(ByteBuffer buffer, EnumSet<RdmaAccess> access) {
        this.buffer = buffer;
        this.accessFlags = access;
        this.localKey = generateLocalKey();
        this.remoteKey = generateRemoteKey();
        this.address = getBufferAddress(buffer);
        this.valid = true;
    }
    
    public ByteBuffer getBuffer() {
        if (!valid) throw new IllegalStateException("Memory region invalidated");
        return buffer;
    }
    
    public int getLocalKey() { return localKey; }
    public int getRemoteKey() { return remoteKey; }
    public long getAddress() { return address; }
    public int getSize() { return buffer.remaining(); }
    
    public boolean hasAccess(RdmaAccess access) {
        return accessFlags.contains(access);
    }
    
    /**
     * Invalidate this memory region
     */
    public abstract void invalidate();
    
    protected abstract int generateLocalKey();
    protected abstract int generateRemoteKey();
    protected abstract long getBufferAddress(ByteBuffer buffer);
    
    @Override
    public void close() {
        invalidate();
        valid = false;
    }
}
```

### 4.3 RDMA Transport
```java
package jcifs.internal.smb2.rdma;

import jcifs.smb.SmbTransport;
import jcifs.internal.smb2.ServerMessageBlock2;

public class RdmaTransport extends SmbTransport {
    private final RdmaConnection rdmaConnection;
    private final RdmaProvider provider;
    private final RdmaBufferManager bufferManager;
    private final RdmaCredits credits;
    
    // RDMA-specific settings
    private int maxReadWriteSize;
    private int maxReceiveSize;
    private boolean rdmaReadWriteEnabled;
    
    public RdmaTransport(CIFSContext context, 
                        InetSocketAddress address,
                        RdmaProvider provider) throws IOException {
        super(context, address.getAddress(), address.getPort());
        
        this.provider = provider;
        this.rdmaConnection = provider.createConnection(address, getLocalAddress());
        this.bufferManager = new RdmaBufferManager(provider);
        this.credits = new RdmaCredits();
        
        // Initialize RDMA parameters
        this.maxReadWriteSize = RdmaCapabilities.DEFAULT_MAX_READ_WRITE_SIZE;
        this.maxReceiveSize = RdmaCapabilities.DEFAULT_MAX_RECEIVE_SIZE;
        this.rdmaReadWriteEnabled = true;
    }
    
    @Override
    public void connect() throws IOException {
        // Establish RDMA connection
        rdmaConnection.connect();
        
        // Perform RDMA negotiate
        performRdmaNegotiation();
        
        // Continue with SMB negotiate over RDMA
        super.connect();
    }
    
    private void performRdmaNegotiation() throws IOException {
        RdmaNegotiateRequest request = new RdmaNegotiateRequest();
        request.setMinVersion(0x0100);
        request.setMaxVersion(0x0100);
        request.setCreditsRequested(credits.getInitialCredits());
        request.setPreferredSendSize(maxReceiveSize);
        request.setMaxReceiveSize(maxReceiveSize);
        request.setMaxFragmentedSize(rdmaConnection.maxFragmentedSize);
        
        RdmaNegotiateResponse response = rdmaConnection.negotiate(request);
        
        if (!response.isSuccess()) {
            throw new IOException("RDMA negotiation failed: " + response.getStatus());
        }
        
        // Update connection parameters based on negotiation
        credits.setCreditsGranted(response.getCreditsGranted());
        maxReadWriteSize = Math.min(maxReadWriteSize, response.getMaxReadWriteSize());
        maxReceiveSize = Math.min(maxReceiveSize, response.getMaxReceiveSize());
    }
    
    @Override
    protected void doSend(ServerMessageBlock2 request) throws IOException {
        if (shouldUseRdmaReadWrite(request)) {
            sendWithRdmaReadWrite(request);
        } else {
            sendWithRdmaSendReceive(request);
        }
    }
    
    private boolean shouldUseRdmaReadWrite(ServerMessageBlock2 request) {
        if (!rdmaReadWriteEnabled) return false;
        
        int dataSize = getDataSize(request);
        return dataSize > 8192 && dataSize <= maxReadWriteSize;  // Use RDMA for large transfers
    }
    
    private void sendWithRdmaReadWrite(ServerMessageBlock2 request) throws IOException {
        // For large data transfers, use RDMA read/write
        
        if (request instanceof Smb2ReadRequest) {
            handleRdmaRead((Smb2ReadRequest) request);
        } else if (request instanceof Smb2WriteRequest) {
            handleRdmaWrite((Smb2WriteRequest) request);
        } else {
            // Fall back to send/receive for non-data operations
            sendWithRdmaSendReceive(request);
        }
    }
    
    private void handleRdmaRead(Smb2ReadRequest request) throws IOException {
        // Allocate buffer for read data
        ByteBuffer readBuffer = bufferManager.allocateBuffer(request.getLength());
        RdmaMemoryRegion readRegion = provider.registerMemory(readBuffer, 
            EnumSet.of(RdmaAccess.LOCAL_WRITE, RdmaAccess.REMOTE_WRITE));
        
        try {
            // Create SMB2 Read request with RDMA read channel info
            request.addRdmaChannelInfo(readRegion.getRemoteKey(), 
                                     readRegion.getAddress(),
                                     readRegion.getSize());
            
            // Send request header via RDMA send
            sendWithRdmaSendReceive(request);
            
            // Wait for server to write data directly to our buffer via RDMA
            // No additional receive needed - data written directly to memory
            
            // Create response with data from RDMA buffer
            Smb2ReadResponse response = new Smb2ReadResponse();
            response.setData(readBuffer.array(), 0, request.getLength());
            
            // Notify waiting thread
            request.setResponse(response);
            
        } finally {
            readRegion.close();
            bufferManager.releaseBuffer(readBuffer);
        }
    }
    
    private void handleRdmaWrite(Smb2WriteRequest request) throws IOException {
        // Register write data buffer for RDMA
        ByteBuffer writeBuffer = ByteBuffer.wrap(request.getData());
        RdmaMemoryRegion writeRegion = provider.registerMemory(writeBuffer,
            EnumSet.of(RdmaAccess.LOCAL_READ, RdmaAccess.REMOTE_READ));
        
        try {
            // Add RDMA read channel info to request
            request.addRdmaChannelInfo(writeRegion.getRemoteKey(),
                                     writeRegion.getAddress(),
                                     writeRegion.getSize());
            
            // Send request header (server will read data directly via RDMA)
            sendWithRdmaSendReceive(request);
            
        } finally {
            writeRegion.close();
        }
    }
    
    private void sendWithRdmaSendReceive(ServerMessageBlock2 request) throws IOException {
        // Traditional send/receive over RDMA
        
        // Wait for send credit
        if (!rdmaConnection.canSend()) {
            waitForSendCredit();
        }
        
        // Serialize request
        ByteBuffer requestBuffer = serializeRequest(request);
        
        // Register buffer if needed
        RdmaMemoryRegion sendRegion = bufferManager.getSendRegion(requestBuffer.remaining());
        sendRegion.getBuffer().put(requestBuffer);
        sendRegion.getBuffer().flip();
        
        try {
            // Send via RDMA
            rdmaConnection.send(sendRegion.getBuffer(), sendRegion);
            rdmaConnection.consumeSendCredit();
            
            // Receive response
            ByteBuffer responseBuffer = rdmaConnection.receive(getResponseTimeout());
            
            // Parse response
            ServerMessageBlock2 response = parseResponse(responseBuffer);
            request.setResponse(response);
            
        } finally {
            bufferManager.releaseSendRegion(sendRegion);
        }
    }
    
    private void waitForSendCredit() throws IOException {
        long deadline = System.currentTimeMillis() + 5000;  // 5 second timeout
        
        while (!rdmaConnection.canSend() && System.currentTimeMillis() < deadline) {
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted waiting for send credit", e);
            }
        }
        
        if (!rdmaConnection.canSend()) {
            throw new IOException("Timeout waiting for RDMA send credit");
        }
    }
    
    @Override
    public void disconnect() throws IOException {
        try {
            rdmaConnection.close();
        } finally {
            bufferManager.cleanup();
            super.disconnect();
        }
    }
    
    public RdmaProvider getProvider() {
        return provider;
    }
    
    public RdmaConnection getConnection() {
        return rdmaConnection;
    }
}
```

### 4.4 RDMA Buffer Manager
```java
package jcifs.internal.smb2.rdma;

import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;

public class RdmaBufferManager {
    private final RdmaProvider provider;
    private final ConcurrentLinkedQueue<RdmaMemoryRegion> availableSendRegions;
    private final ConcurrentLinkedQueue<RdmaMemoryRegion> availableReceiveRegions;
    private final AtomicLong totalAllocated;
    private final AtomicLong totalReleased;
    
    // Buffer pool configuration
    private final int initialSendBuffers = 32;
    private final int initialReceiveBuffers = 64;
    private final int sendBufferSize = 65536;      // 64KB
    private final int receiveBufferSize = 65536;   // 64KB
    
    public RdmaBufferManager(RdmaProvider provider) {
        this.provider = provider;
        this.availableSendRegions = new ConcurrentLinkedQueue<>();
        this.availableReceiveRegions = new ConcurrentLinkedQueue<>();
        this.totalAllocated = new AtomicLong();
        this.totalReleased = new AtomicLong();
        
        // Pre-allocate buffer pool
        initializeBufferPool();
    }
    
    private void initializeBufferPool() {
        // Allocate send buffers
        for (int i = 0; i < initialSendBuffers; i++) {
            try {
                ByteBuffer buffer = ByteBuffer.allocateDirect(sendBufferSize);
                RdmaMemoryRegion region = provider.registerMemory(buffer,
                    EnumSet.of(RdmaAccess.LOCAL_READ, RdmaAccess.REMOTE_READ));
                availableSendRegions.offer(region);
                totalAllocated.incrementAndGet();
            } catch (IOException e) {
                log.warn("Failed to pre-allocate send buffer", e);
            }
        }
        
        // Allocate receive buffers
        for (int i = 0; i < initialReceiveBuffers; i++) {
            try {
                ByteBuffer buffer = ByteBuffer.allocateDirect(receiveBufferSize);
                RdmaMemoryRegion region = provider.registerMemory(buffer,
                    EnumSet.of(RdmaAccess.LOCAL_WRITE, RdmaAccess.REMOTE_WRITE));
                availableReceiveRegions.offer(region);
                totalAllocated.incrementAndGet();
            } catch (IOException e) {
                log.warn("Failed to pre-allocate receive buffer", e);
            }
        }
    }
    
    public RdmaMemoryRegion getSendRegion(int minSize) throws IOException {
        if (minSize <= sendBufferSize) {
            RdmaMemoryRegion region = availableSendRegions.poll();
            if (region != null) {
                region.getBuffer().clear();
                return region;
            }
        }
        
        // Allocate new buffer
        ByteBuffer buffer = ByteBuffer.allocateDirect(Math.max(minSize, sendBufferSize));
        RdmaMemoryRegion region = provider.registerMemory(buffer,
            EnumSet.of(RdmaAccess.LOCAL_READ, RdmaAccess.REMOTE_READ));
        totalAllocated.incrementAndGet();
        return region;
    }
    
    public void releaseSendRegion(RdmaMemoryRegion region) {
        if (region.getSize() == sendBufferSize && availableSendRegions.size() < initialSendBuffers * 2) {
            availableSendRegions.offer(region);
        } else {
            region.close();
            totalReleased.incrementAndGet();
        }
    }
    
    public RdmaMemoryRegion getReceiveRegion() throws IOException {
        RdmaMemoryRegion region = availableReceiveRegions.poll();
        if (region != null) {
            region.getBuffer().clear();
            return region;
        }
        
        // Allocate new buffer
        ByteBuffer buffer = ByteBuffer.allocateDirect(receiveBufferSize);
        RdmaMemoryRegion region = provider.registerMemory(buffer,
            EnumSet.of(RdmaAccess.LOCAL_WRITE, RdmaAccess.REMOTE_WRITE));
        totalAllocated.incrementAndGet();
        return region;
    }
    
    public void releaseReceiveRegion(RdmaMemoryRegion region) {
        if (availableReceiveRegions.size() < initialReceiveBuffers * 2) {
            availableReceiveRegions.offer(region);
        } else {
            region.close();
            totalReleased.incrementAndGet();
        }
    }
    
    public ByteBuffer allocateBuffer(int size) {
        return ByteBuffer.allocateDirect(size);
    }
    
    public void releaseBuffer(ByteBuffer buffer) {
        // For direct buffers, we rely on GC
        // Could implement a more sophisticated buffer pool here
    }
    
    public void cleanup() {
        // Clean up all pooled regions
        RdmaMemoryRegion region;
        
        while ((region = availableSendRegions.poll()) != null) {
            region.close();
            totalReleased.incrementAndGet();
        }
        
        while ((region = availableReceiveRegions.poll()) != null) {
            region.close();
            totalReleased.incrementAndGet();
        }
    }
    
    public long getTotalAllocated() { return totalAllocated.get(); }
    public long getTotalReleased() { return totalReleased.get(); }
    public long getActiveRegions() { return totalAllocated.get() - totalReleased.get(); }
}
```

### 4.5 RDMA Provider Implementations

#### 4.5.1 DiSNI Provider (InfiniBand/RoCE)
```java
package jcifs.internal.smb2.rdma.disni;

import com.ibm.disni.*;
import com.ibm.disni.verbs.*;

public class DisniRdmaProvider implements RdmaProvider {
    private RdmaActiveEndpointGroup<DisniRdmaEndpoint> endpointGroup;
    private RdmaActiveEndpoint endpoint;
    private boolean initialized = false;
    
    @Override
    public boolean isAvailable() {
        try {
            // Check if DiSNI is available
            Class.forName("com.ibm.disni.RdmaActiveEndpointGroup");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }
    
    @Override
    public Set<RdmaCapability> getSupportedCapabilities() {
        return EnumSet.allOf(RdmaCapability.class);
    }
    
    @Override
    public RdmaConnection createConnection(InetSocketAddress remote, 
                                          InetSocketAddress local) throws IOException {
        ensureInitialized();
        return new DisniRdmaConnection(remote, local, endpointGroup);
    }
    
    @Override
    public RdmaMemoryRegion registerMemory(ByteBuffer buffer, 
                                          EnumSet<RdmaAccess> access) throws IOException {
        ensureInitialized();
        return new DisniMemoryRegion(buffer, access, endpoint);
    }
    
    private void ensureInitialized() throws IOException {
        if (!initialized) {
            try {
                // Initialize DiSNI
                endpointGroup = new RdmaActiveEndpointGroup<DisniRdmaEndpoint>(
                    1000, false, 128, 4, 128);
                endpointGroup.init(new DisniRdmaEndpointFactory());
                initialized = true;
            } catch (Exception e) {
                throw new IOException("Failed to initialize DiSNI", e);
            }
        }
    }
    
    @Override
    public String getProviderName() {
        return "DiSNI (InfiniBand/RoCE)";
    }
    
    @Override
    public int getMaxMessageSize() {
        return 2147483647;  // 2GB - DiSNI limit
    }
    
    @Override
    public void shutdown() {
        if (endpointGroup != null) {
            try {
                endpointGroup.close();
            } catch (Exception e) {
                log.error("Error shutting down DiSNI", e);
            }
        }
        initialized = false;
    }
}

class DisniRdmaConnection extends RdmaConnection {
    private final RdmaActiveEndpoint endpoint;
    private final RdmaActiveEndpointGroup<DisniRdmaEndpoint> group;
    
    public DisniRdmaConnection(InetSocketAddress remote, InetSocketAddress local,
                              RdmaActiveEndpointGroup<DisniRdmaEndpoint> group) throws IOException {
        super(remote, local);
        this.group = group;
        this.endpoint = group.createEndpoint();
    }
    
    @Override
    public void connect() throws IOException {
        try {
            endpoint.connect(remoteAddress, 1000);  // 1 second timeout
            state = RdmaConnectionState.CONNECTED;
        } catch (Exception e) {
            throw new IOException("RDMA connection failed", e);
        }
    }
    
    @Override
    public void send(ByteBuffer data, RdmaMemoryRegion region) throws IOException {
        try {
            DisniMemoryRegion disniRegion = (DisniMemoryRegion) region;
            IbvSendWR sendWR = new IbvSendWR();
            sendWR.setWr_id(System.nanoTime());
            sendWR.setOpcode(IbvSendWR.IbvWrOpcode.IBV_WR_SEND.ordinal());
            sendWR.setSend_flags(IbvSendWR.IBV_SEND_SIGNALED);
            
            LinkedList<IbvSge> sgeList = new LinkedList<>();
            IbvSge sge = new IbvSge();
            sge.setAddr(disniRegion.getAddress());
            sge.setLength(data.remaining());
            sge.setLkey(disniRegion.getLocalKey());
            sgeList.add(sge);
            
            sendWR.setSg_list(sgeList);
            endpoint.postSend(Arrays.asList(sendWR)).execute().free();
            
        } catch (Exception e) {
            throw new IOException("RDMA send failed", e);
        }
    }
    
    @Override
    public ByteBuffer receive(int timeout) throws IOException {
        try {
            RdmaCompletionEvent event = endpoint.getCqProcessor().getCqEvent(timeout);
            if (event != null) {
                return event.getBuffer();
            }
            return null;
        } catch (Exception e) {
            throw new IOException("RDMA receive failed", e);
        }
    }
    
    // ... other RDMA operation implementations
}
```

#### 4.5.2 Fallback TCP Provider
```java
package jcifs.internal.smb2.rdma.tcp;

public class TcpRdmaProvider implements RdmaProvider {
    @Override
    public boolean isAvailable() {
        return true;  // TCP is always available
    }
    
    @Override
    public Set<RdmaCapability> getSupportedCapabilities() {
        // TCP fallback only supports send/receive
        return EnumSet.of(RdmaCapability.RDMA_SEND_RECEIVE);
    }
    
    @Override
    public RdmaConnection createConnection(InetSocketAddress remote, 
                                          InetSocketAddress local) throws IOException {
        return new TcpRdmaConnection(remote, local);
    }
    
    @Override
    public RdmaMemoryRegion registerMemory(ByteBuffer buffer, 
                                          EnumSet<RdmaAccess> access) throws IOException {
        // TCP doesn't need real memory registration
        return new TcpMemoryRegion(buffer, access);
    }
    
    @Override
    public String getProviderName() {
        return "TCP Fallback";
    }
    
    @Override
    public int getMaxMessageSize() {
        return 65536;  // 64KB for TCP
    }
    
    @Override
    public void shutdown() {
        // Nothing to clean up for TCP
    }
}
```

## 5. Integration with Existing Code

### 5.1 Transport Selection
```java
// In SmbTransportPool.java
public SmbTransport createTransport(CIFSContext context, 
                                   InetSocketAddress address) throws IOException {
    Configuration config = context.getConfig();
    
    if (config.isUseRDMA()) {
        RdmaProvider provider = selectRdmaProvider();
        if (provider != null && provider.isAvailable()) {
            try {
                return new RdmaTransport(context, address, provider);
            } catch (IOException e) {
                log.warn("Failed to create RDMA transport, falling back to TCP", e);
            }
        }
    }
    
    // Fall back to TCP
    return new SmbTransport(context, address.getAddress(), address.getPort());
}

private RdmaProvider selectRdmaProvider() {
    // Try providers in order of preference
    List<RdmaProvider> providers = Arrays.asList(
        new DisniRdmaProvider(),      // InfiniBand/RoCE
        new JxioRdmaProvider(),       // Alternative RDMA library
        new TcpRdmaProvider()         // TCP fallback
    );
    
    for (RdmaProvider provider : providers) {
        if (provider.isAvailable()) {
            log.info("Selected RDMA provider: {}", provider.getProviderName());
            return provider;
        }
    }
    
    return null;
}
```

### 5.2 SMB2 Read/Write with RDMA
```java
// In Smb2ReadRequest.java
private RdmaChannelInfo rdmaChannelInfo;

public void addRdmaChannelInfo(int remoteKey, long address, int length) {
    this.rdmaChannelInfo = new RdmaChannelInfo(remoteKey, address, length);
}

@Override
protected int writePayload(byte[] dst, int dstIndex) {
    int written = super.writePayload(dst, dstIndex);
    
    if (rdmaChannelInfo != null) {
        // Add RDMA read channel info
        writeInt4(dst, dstIndex + written, rdmaChannelInfo.getRemoteKey());
        written += 4;
        writeInt8(dst, dstIndex + written, rdmaChannelInfo.getAddress());
        written += 8;
        writeInt4(dst, dstIndex + written, rdmaChannelInfo.getLength());
        written += 4;
    }
    
    return written;
}

public static class RdmaChannelInfo {
    private final int remoteKey;
    private final long address;
    private final int length;
    
    public RdmaChannelInfo(int key, long addr, int len) {
        this.remoteKey = key;
        this.address = addr;
        this.length = len;
    }
    
    // Getters...
}
```

## 6. Configuration

### 6.1 Configuration Properties
```java
// In PropertyConfiguration.java
public static final String USE_RDMA = "jcifs.smb.client.useRDMA";
public static final String RDMA_PROVIDER = "jcifs.smb.client.rdmaProvider";
public static final String RDMA_READ_WRITE_THRESHOLD = "jcifs.smb.client.rdmaReadWriteThreshold";
public static final String RDMA_MAX_SEND_SIZE = "jcifs.smb.client.rdmaMaxSendSize";
public static final String RDMA_MAX_RECEIVE_SIZE = "jcifs.smb.client.rdmaMaxReceiveSize";
public static final String RDMA_CREDITS = "jcifs.smb.client.rdmaCredits";

public boolean isUseRDMA() {
    String value = getProperty(USE_RDMA, "auto");
    return "true".equals(value) || ("auto".equals(value) && isRdmaAvailable());
}

public String getRdmaProvider() {
    return getProperty(RDMA_PROVIDER, "auto");  // auto, disni, jxio, tcp
}

public int getRdmaReadWriteThreshold() {
    return getIntProperty(RDMA_READ_WRITE_THRESHOLD, 8192);  // 8KB
}

public int getRdmaMaxSendSize() {
    return getIntProperty(RDMA_MAX_SEND_SIZE, 65536);  // 64KB
}

public int getRdmaMaxReceiveSize() {
    return getIntProperty(RDMA_MAX_RECEIVE_SIZE, 65536);  // 64KB
}

public int getRdmaCredits() {
    return getIntProperty(RDMA_CREDITS, 255);
}

private boolean isRdmaAvailable() {
    return new DisniRdmaProvider().isAvailable() || 
           new JxioRdmaProvider().isAvailable();
}
```

## 7. Testing Strategy

### 7.1 Unit Tests
```java
@Test
public void testRdmaProviderSelection() {
    RdmaProvider provider = RdmaProviderFactory.createProvider("auto");
    assertNotNull(provider);
    assertTrue(provider.isAvailable());
}

@Test
public void testRdmaMemoryRegistration() throws Exception {
    RdmaProvider provider = new DisniRdmaProvider();
    assumeTrue(provider.isAvailable());
    
    ByteBuffer buffer = ByteBuffer.allocateDirect(4096);
    RdmaMemoryRegion region = provider.registerMemory(buffer, 
        EnumSet.of(RdmaAccess.LOCAL_READ, RdmaAccess.REMOTE_READ));
    
    assertNotNull(region);
    assertEquals(4096, region.getSize());
    assertTrue(region.hasAccess(RdmaAccess.LOCAL_READ));
    
    region.close();
}

@Test
public void testRdmaBufferManager() throws Exception {
    RdmaProvider provider = new TcpRdmaProvider();  // Use TCP for testing
    RdmaBufferManager manager = new RdmaBufferManager(provider);
    
    // Test buffer allocation
    RdmaMemoryRegion region = manager.getSendRegion(1024);
    assertNotNull(region);
    assertTrue(region.getSize() >= 1024);
    
    // Test buffer release
    manager.releaseSendRegion(region);
    
    // Test reuse
    RdmaMemoryRegion region2 = manager.getSendRegion(1024);
    assertNotNull(region2);
    
    manager.cleanup();
}
```

### 7.2 Integration Tests
```java
@Test
@EnabledIfSystemProperty(named = "rdma.test.enabled", matches = "true")
public void testRdmaLargeFileTransfer() throws Exception {
    CIFSContext context = getTestContext();
    context.getConfig().setProperty("jcifs.smb.client.useRDMA", "true");
    
    SmbFile file = new SmbFile("smb://server/share/largefile.dat", context);
    
    // Measure RDMA transfer performance
    byte[] data = new byte[10485760];  // 10MB
    Arrays.fill(data, (byte)0x42);
    
    long start = System.currentTimeMillis();
    
    try (OutputStream os = file.getOutputStream()) {
        os.write(data);
    }
    
    long writeTime = System.currentTimeMillis() - start;
    
    // Read back
    start = System.currentTimeMillis();
    byte[] readData = new byte[data.length];
    
    try (InputStream is = file.getInputStream()) {
        is.read(readData);
    }
    
    long readTime = System.currentTimeMillis() - start;
    
    assertArrayEquals(data, readData);
    
    // RDMA should be faster than TCP for large transfers
    log.info("RDMA Write: {}ms, Read: {}ms", writeTime, readTime);
}

@Test
public void testRdmaFallbackToTcp() throws Exception {
    // Test that we properly fall back to TCP when RDMA is not available
    CIFSContext context = getTestContext();
    context.getConfig().setProperty("jcifs.smb.client.useRDMA", "true");
    context.getConfig().setProperty("jcifs.smb.client.rdmaProvider", "nonexistent");
    
    SmbFile file = new SmbFile("smb://server/share/test.txt", context);
    
    // Should work even if RDMA provider is not available
    file.createNewFile();
    assertTrue(file.exists());
}
```

## 8. Performance Monitoring

### 8.1 RDMA Statistics
```java
public class RdmaStatistics {
    private final AtomicLong rdmaReads = new AtomicLong();
    private final AtomicLong rdmaWrites = new AtomicLong();
    private final AtomicLong rdmaSends = new AtomicLong();
    private final AtomicLong rdmaReceives = new AtomicLong();
    private final AtomicLong bytesTransferred = new AtomicLong();
    private final AtomicLong operationErrors = new AtomicLong();
    
    public void recordRdmaRead(int bytes) {
        rdmaReads.incrementAndGet();
        bytesTransferred.addAndGet(bytes);
    }
    
    public void recordRdmaWrite(int bytes) {
        rdmaWrites.incrementAndGet();
        bytesTransferred.addAndGet(bytes);
    }
    
    public void recordError() {
        operationErrors.incrementAndGet();
    }
    
    public double getErrorRate() {
        long total = rdmaReads.get() + rdmaWrites.get() + rdmaSends.get() + rdmaReceives.get();
        if (total == 0) return 0.0;
        return (double) operationErrors.get() / total;
    }
    
    // Getters for all statistics...
}
```

## 9. Error Handling and Fallback

### 9.1 RDMA Error Recovery
```java
public class RdmaErrorHandler {
    public void handleRdmaError(RdmaConnection connection, Exception error) {
        log.warn("RDMA error occurred: {}", error.getMessage());
        
        if (isRecoverableError(error)) {
            // Attempt to recover connection
            try {
                connection.reset();
                log.info("RDMA connection recovered");
            } catch (Exception e) {
                log.error("Failed to recover RDMA connection", e);
                fallbackToTcp(connection);
            }
        } else {
            // Non-recoverable error, fall back to TCP
            fallbackToTcp(connection);
        }
    }
    
    private boolean isRecoverableError(Exception error) {
        // Check if error is recoverable (temporary network issue, etc.)
        return error instanceof SocketTimeoutException
            || error.getMessage().contains("retry");
    }
    
    private void fallbackToTcp(RdmaConnection connection) {
        log.info("Falling back to TCP transport");
        // Switch transport to TCP
        // This would require transport factory modification
    }
}
```

## 10. Security Considerations

### 10.1 RDMA Security
```java
public class RdmaSecurityManager {
    public void validateMemoryAccess(RdmaMemoryRegion region, RdmaAccess requestedAccess) {
        if (!region.hasAccess(requestedAccess)) {
            throw new SecurityException("Insufficient RDMA memory access rights");
        }
    }
    
    public void validateRemoteAccess(long remoteAddress, int length, int remoteKey) {
        // Validate that remote memory access is authorized
        // This would integrate with SMB3 encryption/signing
        if (!isAuthorizedAccess(remoteAddress, length, remoteKey)) {
            throw new SecurityException("Unauthorized RDMA remote access");
        }
    }
    
    private boolean isAuthorizedAccess(long address, int length, int key) {
        // Implementation would check against established security context
        return true;  // Simplified
    }
}
```