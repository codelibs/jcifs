# Witness Protocol Feature - Detailed Design Document

## 1. Overview

The SMB Witness Protocol enables rapid notification of resource changes in a clustered file server environment. It provides fast failover capabilities by allowing clients to register for notifications about server node availability, share movement, and other critical cluster events.

## 2. Protocol Specification Reference

- **MS-SWN**: Service Witness Protocol Specification
- **MS-SMB2 Section 3.2.4.24**: FSCTL_SRV_REQUEST_RESUME_KEY
- **MS-SMB2 Section 3.3.5.15.12**: Cluster Reconnect
- **MS-RRP**: Windows Remote Registry Protocol (for witness service discovery)

## 3. Witness Architecture

### 3.1 Witness Service Types
```java
public enum WitnessServiceType {
    CLUSTER_WITNESS,     // Cluster-aware witness service
    FILE_SERVER_WITNESS, // Individual file server witness
    SCALE_OUT_WITNESS,   // Scale-out file server witness
    DFS_WITNESS         // DFS namespace witness
}

public enum WitnessVersion {
    VERSION_1(0x00010001),  // Windows Server 2012
    VERSION_2(0x00020000);  // Windows Server 2012 R2+
    
    private final int version;
    
    WitnessVersion(int version) {
        this.version = version;
    }
    
    public int getValue() { return version; }
}
```

### 3.2 Witness Event Types
```java
public enum WitnessEventType {
    RESOURCE_CHANGE(1),        // Resource state changed
    CLIENT_MOVE(2),           // Client should move to different node
    SHARE_MOVE(3),            // Share moved to different node
    IP_CHANGE(4),             // IP address changed
    SHARE_DELETE(5),          // Share deleted
    NODE_UNAVAILABLE(6),      // Cluster node unavailable
    NODE_AVAILABLE(7);        // Cluster node available
    
    private final int value;
    
    WitnessEventType(int value) {
        this.value = value;
    }
    
    public int getValue() { return value; }
}
```

## 4. Data Structures

### 4.1 Witness Registration
```java
package jcifs.internal.witness;

import java.net.InetAddress;
import java.util.concurrent.atomic.AtomicLong;

public class WitnessRegistration {
    private final String registrationId;
    private final String shareName;
    private final InetAddress serverAddress;
    private final WitnessServiceType serviceType;
    private final WitnessVersion version;
    private final long registrationTime;
    private final AtomicLong sequenceNumber;
    
    // Registration flags
    public static final int WITNESS_REGISTER_NONE = 0x00000000;
    public static final int WITNESS_REGISTER_IP_NOTIFICATION = 0x00000001;
    
    // Registration state
    private volatile WitnessRegistrationState state;
    private volatile long lastHeartbeat;
    private int flags;
    
    public enum WitnessRegistrationState {
        REGISTERING,
        REGISTERED,
        UNREGISTERING,
        FAILED,
        EXPIRED
    }
    
    public WitnessRegistration(String shareName, InetAddress serverAddress, 
                              WitnessServiceType serviceType) {
        this.registrationId = generateRegistrationId();
        this.shareName = shareName;
        this.serverAddress = serverAddress;
        this.serviceType = serviceType;
        this.version = WitnessVersion.VERSION_2;  // Use latest by default
        this.registrationTime = System.currentTimeMillis();
        this.sequenceNumber = new AtomicLong(0);
        this.state = WitnessRegistrationState.REGISTERING;
        this.lastHeartbeat = registrationTime;
        this.flags = WITNESS_REGISTER_IP_NOTIFICATION;
    }
    
    private String generateRegistrationId() {
        return "REG-" + System.currentTimeMillis() + "-" + 
               Integer.toHexString(System.identityHashCode(this));
    }
    
    public long getNextSequenceNumber() {
        return sequenceNumber.incrementAndGet();
    }
    
    public void updateHeartbeat() {
        this.lastHeartbeat = System.currentTimeMillis();
    }
    
    public boolean isExpired(long timeoutMs) {
        return System.currentTimeMillis() - lastHeartbeat > timeoutMs;
    }
    
    // Getters and setters...
    public String getRegistrationId() { return registrationId; }
    public String getShareName() { return shareName; }
    public InetAddress getServerAddress() { return serverAddress; }
    public WitnessServiceType getServiceType() { return serviceType; }
    public WitnessRegistrationState getState() { return state; }
    public void setState(WitnessRegistrationState state) { this.state = state; }
}
```

### 4.2 Witness Notification
```java
package jcifs.internal.witness;

import java.util.List;
import java.util.ArrayList;

public class WitnessNotification {
    private final WitnessEventType eventType;
    private final long timestamp;
    private final String resourceName;
    private final List<WitnessIPAddress> newIPAddresses;
    private final List<WitnessIPAddress> oldIPAddresses;
    private final String clientAccessPoint;
    private final int flags;
    
    // Notification flags
    public static final int WITNESS_RESOURCE_STATE_UNKNOWN = 0x00000000;
    public static final int WITNESS_RESOURCE_STATE_AVAILABLE = 0x00000001;
    public static final int WITNESS_RESOURCE_STATE_UNAVAILABLE = 0x000000FF;
    
    public WitnessNotification(WitnessEventType eventType, String resourceName) {
        this.eventType = eventType;
        this.resourceName = resourceName;
        this.timestamp = System.currentTimeMillis();
        this.newIPAddresses = new ArrayList<>();
        this.oldIPAddresses = new ArrayList<>();
        this.clientAccessPoint = null;
        this.flags = WITNESS_RESOURCE_STATE_UNKNOWN;
    }
    
    public static class WitnessIPAddress {
        private final InetAddress address;
        private final int flags;
        
        public static final int IPV4 = 0x01;
        public static final int IPV6 = 0x02;
        
        public WitnessIPAddress(InetAddress address) {
            this.address = address;
            this.flags = address.getAddress().length == 4 ? IPV4 : IPV6;
        }
        
        public InetAddress getAddress() { return address; }
        public int getFlags() { return flags; }
        public boolean isIPv4() { return (flags & IPV4) != 0; }
        public boolean isIPv6() { return (flags & IPV6) != 0; }
    }
    
    public void addNewIPAddress(InetAddress address) {
        newIPAddresses.add(new WitnessIPAddress(address));
    }
    
    public void addOldIPAddress(InetAddress address) {
        oldIPAddresses.add(new WitnessIPAddress(address));
    }
    
    // Getters...
    public WitnessEventType getEventType() { return eventType; }
    public String getResourceName() { return resourceName; }
    public long getTimestamp() { return timestamp; }
    public List<WitnessIPAddress> getNewIPAddresses() { return newIPAddresses; }
    public List<WitnessIPAddress> getOldIPAddresses() { return oldIPAddresses; }
}
```

### 4.3 Witness Client
```java
package jcifs.internal.witness;

import jcifs.dcerpc.*;
import jcifs.dcerpc.rpc.*;
import java.util.concurrent.*;

public class WitnessClient implements AutoCloseable {
    private final InetAddress witnessServer;
    private final int port;
    private final CIFSContext context;
    private final ConcurrentHashMap<String, WitnessRegistration> registrations;
    private final ConcurrentHashMap<String, WitnessNotificationListener> listeners;
    private final ScheduledExecutorService scheduler;
    private final WitnessRpcClient rpcClient;
    
    // Witness service endpoint
    private static final String WITNESS_SERVICE_UUID = "ccd8c074-d0e5-4a40-92b4-d074faa6ba28";
    private static final int DEFAULT_WITNESS_PORT = 135;  // RPC endpoint mapper
    
    public interface WitnessNotificationListener {
        void onWitnessNotification(WitnessNotification notification);
        void onRegistrationFailed(WitnessRegistration registration, Exception error);
        void onRegistrationExpired(WitnessRegistration registration);
    }
    
    public WitnessClient(InetAddress witnessServer, CIFSContext context) {
        this.witnessServer = witnessServer;
        this.port = DEFAULT_WITNESS_PORT;
        this.context = context;
        this.registrations = new ConcurrentHashMap<>();
        this.listeners = new ConcurrentHashMap<>();
        this.scheduler = Executors.newScheduledThreadPool(2);
        this.rpcClient = new WitnessRpcClient(witnessServer, context);
        
        // Schedule periodic tasks
        schedulePeriodicTasks();
    }
    
    private void schedulePeriodicTasks() {
        // Heartbeat monitoring
        scheduler.scheduleAtFixedRate(this::checkHeartbeats, 30, 30, TimeUnit.SECONDS);
        
        // Registration monitoring
        scheduler.scheduleAtFixedRate(this::monitorRegistrations, 10, 10, TimeUnit.SECONDS);
    }
    
    public CompletableFuture<WitnessRegistration> registerForNotifications(
            String shareName, 
            InetAddress serverAddress,
            WitnessNotificationListener listener) {
        
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Create registration
                WitnessRegistration registration = new WitnessRegistration(
                    shareName, serverAddress, WitnessServiceType.FILE_SERVER_WITNESS);
                
                // Perform RPC registration
                WitnessRegisterRequest request = new WitnessRegisterRequest();
                request.setVersion(registration.getVersion().getValue());
                request.setShareName(shareName);
                request.setServerAddress(serverAddress.getHostAddress());
                request.setFlags(registration.getFlags());
                
                WitnessRegisterResponse response = rpcClient.register(request);
                
                if (response.isSuccess()) {
                    registration.setState(WitnessRegistrationState.REGISTERED);
                    registrations.put(registration.getRegistrationId(), registration);
                    listeners.put(registration.getRegistrationId(), listener);
                    
                    log.info("Successfully registered for witness notifications: {}", 
                        registration.getRegistrationId());
                    
                    return registration;
                } else {
                    throw new IOException("Witness registration failed: " + response.getError());
                }
                
            } catch (Exception e) {
                log.error("Failed to register for witness notifications", e);
                throw new RuntimeException(e);
            }
        });
    }
    
    public CompletableFuture<Void> unregister(WitnessRegistration registration) {
        return CompletableFuture.runAsync(() -> {
            try {
                registration.setState(WitnessRegistrationState.UNREGISTERING);
                
                WitnessUnregisterRequest request = new WitnessUnregisterRequest();
                request.setRegistrationId(registration.getRegistrationId());
                
                WitnessUnregisterResponse response = rpcClient.unregister(request);
                
                if (response.isSuccess()) {
                    registrations.remove(registration.getRegistrationId());
                    listeners.remove(registration.getRegistrationId());
                    
                    log.info("Successfully unregistered witness: {}", 
                        registration.getRegistrationId());
                } else {
                    log.warn("Failed to unregister witness: {}", response.getError());
                }
                
            } catch (Exception e) {
                log.error("Error during witness unregistration", e);
            }
        });
    }
    
    public void processNotification(WitnessNotification notification) {
        log.info("Received witness notification: {} for resource: {}", 
            notification.getEventType(), notification.getResourceName());
        
        // Find registrations that match this notification
        for (Map.Entry<String, WitnessRegistration> entry : registrations.entrySet()) {
            WitnessRegistration registration = entry.getValue();
            
            if (shouldDeliverNotification(registration, notification)) {
                WitnessNotificationListener listener = listeners.get(entry.getKey());
                if (listener != null) {
                    try {
                        listener.onWitnessNotification(notification);
                    } catch (Exception e) {
                        log.error("Error in witness notification listener", e);
                    }
                }
            }
        }
    }
    
    private boolean shouldDeliverNotification(WitnessRegistration registration, 
                                            WitnessNotification notification) {
        // Check if notification is relevant to this registration
        String resourceName = notification.getResourceName();
        String shareName = registration.getShareName();
        
        // Match by share name or server address
        return resourceName.equalsIgnoreCase(shareName) ||
               resourceName.equals(registration.getServerAddress().getHostAddress());
    }
    
    private void checkHeartbeats() {
        long timeout = context.getConfig().getWitnessHeartbeatTimeout();
        
        for (WitnessRegistration registration : registrations.values()) {
            if (registration.isExpired(timeout)) {
                log.warn("Witness registration expired: {}", registration.getRegistrationId());
                
                registration.setState(WitnessRegistrationState.EXPIRED);
                WitnessNotificationListener listener = listeners.get(registration.getRegistrationId());
                
                if (listener != null) {
                    listener.onRegistrationExpired(registration);
                }
                
                // Clean up expired registration
                registrations.remove(registration.getRegistrationId());
                listeners.remove(registration.getRegistrationId());
            }
        }
    }
    
    private void monitorRegistrations() {
        for (WitnessRegistration registration : registrations.values()) {
            if (registration.getState() == WitnessRegistrationState.REGISTERED) {
                // Send periodic heartbeat
                sendHeartbeat(registration);
            }
        }
    }
    
    private void sendHeartbeat(WitnessRegistration registration) {
        try {
            WitnessHeartbeatRequest request = new WitnessHeartbeatRequest();
            request.setRegistrationId(registration.getRegistrationId());
            request.setSequenceNumber(registration.getNextSequenceNumber());
            
            WitnessHeartbeatResponse response = rpcClient.heartbeat(request);
            
            if (response.isSuccess()) {
                registration.updateHeartbeat();
            } else {
                log.warn("Witness heartbeat failed for: {}", registration.getRegistrationId());
            }
            
        } catch (Exception e) {
            log.debug("Heartbeat error for registration: {}", 
                registration.getRegistrationId(), e);
        }
    }
    
    @Override
    public void close() {
        // Unregister all active registrations
        List<CompletableFuture<Void>> unregisterFutures = new ArrayList<>();
        
        for (WitnessRegistration registration : registrations.values()) {
            unregisterFutures.add(unregister(registration));
        }
        
        // Wait for all unregistrations to complete
        try {
            CompletableFuture.allOf(unregisterFutures.toArray(new CompletableFuture[0]))
                .get(10, TimeUnit.SECONDS);
        } catch (Exception e) {
            log.warn("Error during witness client shutdown", e);
        }
        
        // Shutdown scheduler
        scheduler.shutdown();
        
        // Close RPC client
        if (rpcClient != null) {
            rpcClient.close();
        }
    }
}
```

### 4.4 Witness RPC Client
```java
package jcifs.internal.witness;

import jcifs.dcerpc.*;
import jcifs.dcerpc.rpc.*;

public class WitnessRpcClient implements AutoCloseable {
    private final DcerpcHandle handle;
    private final InetAddress serverAddress;
    private final CIFSContext context;
    
    // Witness RPC interface
    private static final String WITNESS_INTERFACE_UUID = "ccd8c074-d0e5-4a40-92b4-d074faa6ba28";
    private static final int WITNESS_INTERFACE_VERSION = 1;
    
    // RPC operation numbers
    private static final int WITNESS_REGISTER = 0;
    private static final int WITNESS_UNREGISTER = 1;
    private static final int WITNESS_ASYNC_NOTIFY = 2;
    private static final int WITNESS_HEARTBEAT = 3;
    
    public WitnessRpcClient(InetAddress serverAddress, CIFSContext context) throws IOException {
        this.serverAddress = serverAddress;
        this.context = context;
        
        try {
            // Create RPC handle to witness service
            this.handle = DcerpcHandle.getHandle(
                "ncacn_ip_tcp:" + serverAddress.getHostAddress() + "[135]",
                WITNESS_INTERFACE_UUID,
                WITNESS_INTERFACE_VERSION,
                context
            );
            
            // Bind to witness interface
            handle.bind();
            
        } catch (Exception e) {
            throw new IOException("Failed to connect to witness service", e);
        }
    }
    
    public WitnessRegisterResponse register(WitnessRegisterRequest request) throws IOException {
        try {
            WitnessRegisterStub stub = new WitnessRegisterStub(request);
            handle.sendrecv(stub);
            return stub.getResponse();
        } catch (Exception e) {
            throw new IOException("Witness register RPC failed", e);
        }
    }
    
    public WitnessUnregisterResponse unregister(WitnessUnregisterRequest request) throws IOException {
        try {
            WitnessUnregisterStub stub = new WitnessUnregisterStub(request);
            handle.sendrecv(stub);
            return stub.getResponse();
        } catch (Exception e) {
            throw new IOException("Witness unregister RPC failed", e);
        }
    }
    
    public WitnessHeartbeatResponse heartbeat(WitnessHeartbeatRequest request) throws IOException {
        try {
            WitnessHeartbeatStub stub = new WitnessHeartbeatStub(request);
            handle.sendrecv(stub);
            return stub.getResponse();
        } catch (Exception e) {
            throw new IOException("Witness heartbeat RPC failed", e);
        }
    }
    
    @Override
    public void close() {
        if (handle != null) {
            try {
                handle.close();
            } catch (Exception e) {
                log.error("Error closing witness RPC handle", e);
            }
        }
    }
    
    // RPC Stub classes for witness operations
    private static class WitnessRegisterStub extends DcerpcMessage {
        private final WitnessRegisterRequest request;
        private WitnessRegisterResponse response;
        
        public WitnessRegisterStub(WitnessRegisterRequest request) {
            this.request = request;
            this.ptype = 0;
            this.flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
        }
        
        @Override
        public int getOpnum() { return WITNESS_REGISTER; }
        
        @Override
        public void encode_in(NdrBuffer buffer) throws NdrException {
            // Encode WitnessRegister request parameters
            buffer.enc_ndr_long(request.getVersion());
            buffer.enc_ndr_string(request.getShareName());
            buffer.enc_ndr_string(request.getServerAddress());
            buffer.enc_ndr_long(request.getFlags());
        }
        
        @Override
        public void decode_out(NdrBuffer buffer) throws NdrException {
            // Decode WitnessRegister response
            response = new WitnessRegisterResponse();
            response.setRegistrationId(buffer.dec_ndr_string());
            response.setReturnCode(buffer.dec_ndr_long());
        }
        
        public WitnessRegisterResponse getResponse() { return response; }
    }
    
    private static class WitnessUnregisterStub extends DcerpcMessage {
        private final WitnessUnregisterRequest request;
        private WitnessUnregisterResponse response;
        
        public WitnessUnregisterStub(WitnessUnregisterRequest request) {
            this.request = request;
            this.ptype = 0;
            this.flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
        }
        
        @Override
        public int getOpnum() { return WITNESS_UNREGISTER; }
        
        @Override
        public void encode_in(NdrBuffer buffer) throws NdrException {
            buffer.enc_ndr_string(request.getRegistrationId());
        }
        
        @Override
        public void decode_out(NdrBuffer buffer) throws NdrException {
            response = new WitnessUnregisterResponse();
            response.setReturnCode(buffer.dec_ndr_long());
        }
        
        public WitnessUnregisterResponse getResponse() { return response; }
    }
    
    private static class WitnessHeartbeatStub extends DcerpcMessage {
        private final WitnessHeartbeatRequest request;
        private WitnessHeartbeatResponse response;
        
        public WitnessHeartbeatStub(WitnessHeartbeatRequest request) {
            this.request = request;
            this.ptype = 0;
            this.flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
        }
        
        @Override
        public int getOpnum() { return WITNESS_HEARTBEAT; }
        
        @Override
        public void encode_in(NdrBuffer buffer) throws NdrException {
            buffer.enc_ndr_string(request.getRegistrationId());
            buffer.enc_ndr_long(request.getSequenceNumber());
        }
        
        @Override
        public void decode_out(NdrBuffer buffer) throws NdrException {
            response = new WitnessHeartbeatResponse();
            response.setSequenceNumber(buffer.dec_ndr_long());
            response.setReturnCode(buffer.dec_ndr_long());
        }
        
        public WitnessHeartbeatResponse getResponse() { return response; }
    }
}

// Request/Response classes
class WitnessRegisterRequest {
    private int version;
    private String shareName;
    private String serverAddress;
    private int flags;
    
    // Getters and setters...
}

class WitnessRegisterResponse {
    private String registrationId;
    private int returnCode;
    
    public boolean isSuccess() { return returnCode == 0; }
    public String getError() { return "Error code: " + returnCode; }
    // Getters and setters...
}

class WitnessUnregisterRequest {
    private String registrationId;
    // Getters and setters...
}

class WitnessUnregisterResponse {
    private int returnCode;
    
    public boolean isSuccess() { return returnCode == 0; }
    public String getError() { return "Error code: " + returnCode; }
}

class WitnessHeartbeatRequest {
    private String registrationId;
    private long sequenceNumber;
    // Getters and setters...
}

class WitnessHeartbeatResponse {
    private long sequenceNumber;
    private int returnCode;
    
    public boolean isSuccess() { return returnCode == 0; }
    // Getters and setters...
}
```

## 5. Integration with Existing Code

### 5.1 Session Integration
```java
// In SmbSession.java
private WitnessClient witnessClient;
private boolean witnessEnabled;

public void initializeWitnessSupport() {
    Configuration config = context.getConfig();
    
    if (!config.isUseWitness()) {
        return;
    }
    
    try {
        // Discover witness service
        InetAddress witnessServer = discoverWitnessService();
        if (witnessServer != null) {
            witnessClient = new WitnessClient(witnessServer, context);
            witnessEnabled = true;
            
            log.info("Initialized witness support with server: {}", witnessServer);
        }
    } catch (Exception e) {
        log.warn("Failed to initialize witness support", e);
    }
}

private InetAddress discoverWitnessService() throws IOException {
    // Try the same server first
    InetAddress serverAddress = transport.getRemoteAddress();
    
    if (isWitnessServiceAvailable(serverAddress)) {
        return serverAddress;
    }
    
    // Query for cluster witness service via DNS
    try {
        String clusterName = getClusterName(serverAddress);
        if (clusterName != null) {
            return InetAddress.getByName(clusterName + "-witness");
        }
    } catch (Exception e) {
        log.debug("Failed to discover cluster witness via DNS", e);
    }
    
    return null;  // No witness service found
}

private boolean isWitnessServiceAvailable(InetAddress address) {
    try (Socket socket = new Socket()) {
        socket.connect(new InetSocketAddress(address, 135), 5000);  // RPC endpoint
        return true;
    } catch (IOException e) {
        return false;
    }
}

public void registerForWitnessNotifications(String shareName) {
    if (!witnessEnabled || witnessClient == null) {
        return;
    }
    
    try {
        InetAddress serverAddress = transport.getRemoteAddress();
        
        witnessClient.registerForNotifications(shareName, serverAddress, 
            new WitnessNotificationHandler())
            .thenAccept(registration -> {
                log.info("Registered for witness notifications: share={}, id={}", 
                    shareName, registration.getRegistrationId());
            })
            .exceptionally(error -> {
                log.error("Failed to register for witness notifications", error);
                return null;
            });
            
    } catch (Exception e) {
        log.error("Error registering for witness notifications", e);
    }
}

private class WitnessNotificationHandler implements WitnessClient.WitnessNotificationListener {
    @Override
    public void onWitnessNotification(WitnessNotification notification) {
        handleWitnessEvent(notification);
    }
    
    @Override
    public void onRegistrationFailed(WitnessRegistration registration, Exception error) {
        log.error("Witness registration failed: {}", registration.getRegistrationId(), error);
    }
    
    @Override
    public void onRegistrationExpired(WitnessRegistration registration) {
        log.warn("Witness registration expired: {}", registration.getRegistrationId());
        // Could attempt re-registration here
    }
}

private void handleWitnessEvent(WitnessNotification notification) {
    log.info("Handling witness event: {} for resource: {}", 
        notification.getEventType(), notification.getResourceName());
    
    switch (notification.getEventType()) {
        case RESOURCE_CHANGE:
            handleResourceChange(notification);
            break;
            
        case CLIENT_MOVE:
            handleClientMove(notification);
            break;
            
        case SHARE_MOVE:
            handleShareMove(notification);
            break;
            
        case IP_CHANGE:
            handleIPChange(notification);
            break;
            
        case NODE_UNAVAILABLE:
            handleNodeUnavailable(notification);
            break;
            
        case NODE_AVAILABLE:
            handleNodeAvailable(notification);
            break;
    }
}

private void handleResourceChange(WitnessNotification notification) {
    // Resource state changed - may need to reconnect
    log.info("Resource change detected for: {}", notification.getResourceName());
    
    // Schedule reconnection attempt
    scheduleReconnection(1000);  // 1 second delay
}

private void handleClientMove(WitnessNotification notification) {
    // Server is asking client to move to different node
    log.info("Client move requested for resource: {}", notification.getResourceName());
    
    List<WitnessNotification.WitnessIPAddress> newAddresses = notification.getNewIPAddresses();
    if (!newAddresses.isEmpty()) {
        // Attempt to connect to new address
        InetAddress newAddress = newAddresses.get(0).getAddress();
        scheduleAddressChange(newAddress);
    }
}

private void handleShareMove(WitnessNotification notification) {
    // Share moved to different server node
    log.info("Share move detected for: {}", notification.getResourceName());
    
    // Similar to client move - try new addresses
    handleClientMove(notification);
}

private void handleIPChange(WitnessNotification notification) {
    // Server IP address changed
    log.info("IP change detected for resource: {}", notification.getResourceName());
    
    List<WitnessNotification.WitnessIPAddress> newAddresses = notification.getNewIPAddresses();
    if (!newAddresses.isEmpty()) {
        InetAddress newAddress = newAddresses.get(0).getAddress();
        scheduleAddressChange(newAddress);
    }
}

private void scheduleReconnection(long delayMs) {
    CompletableFuture.delayedExecutor(delayMs, TimeUnit.MILLISECONDS)
        .execute(() -> {
            try {
                transport.disconnect();
                transport.connect();  // Reconnect
                log.info("Successfully reconnected after witness notification");
            } catch (Exception e) {
                log.error("Failed to reconnect after witness notification", e);
            }
        });
}

private void scheduleAddressChange(InetAddress newAddress) {
    CompletableFuture.runAsync(() -> {
        try {
            // Create new transport to new address
            SmbTransport newTransport = new SmbTransport(context, newAddress, transport.getPort());
            
            // Disconnect old transport
            transport.disconnect();
            
            // Replace with new transport
            this.transport = newTransport;
            newTransport.connect();
            
            log.info("Successfully moved to new server address: {}", newAddress);
            
        } catch (Exception e) {
            log.error("Failed to move to new server address: {}", newAddress, e);
            // Could fall back to original address
        }
    });
}

@Override
public void logoff() throws IOException {
    if (witnessClient != null) {
        witnessClient.close();
    }
    super.logoff();
}
```

### 5.2 Tree Connection Integration
```java
// In SmbTree.java
public void connectWithWitnessSupport() throws IOException {
    // Perform normal tree connection
    super.connect();
    
    // Register for witness notifications for this share
    if (session.isWitnessEnabled()) {
        String shareName = getPath();  // e.g., "\\server\share"
        session.registerForWitnessNotifications(shareName);
    }
}
```

### 5.3 File Handle Integration
```java
// In SmbFile.java
@Override
protected void handleConnectionLoss(IOException error) {
    if (tree.getSession().isWitnessEnabled()) {
        log.info("Connection lost, waiting for witness notification before retry");
        
        // Wait briefly for witness notification before retrying
        try {
            Thread.sleep(2000);  // 2 second grace period
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // Proceed with normal error handling/retry
    super.handleConnectionLoss(error);
}
```

## 6. Configuration

### 6.1 Configuration Properties
```java
// In PropertyConfiguration.java
public static final String USE_WITNESS = "jcifs.smb.client.useWitness";
public static final String WITNESS_HEARTBEAT_TIMEOUT = "jcifs.smb.client.witnessHeartbeatTimeout";
public static final String WITNESS_REGISTRATION_TIMEOUT = "jcifs.smb.client.witnessRegistrationTimeout";
public static final String WITNESS_RECONNECT_DELAY = "jcifs.smb.client.witnessReconnectDelay";
public static final String WITNESS_SERVICE_DISCOVERY = "jcifs.smb.client.witnessServiceDiscovery";

public boolean isUseWitness() {
    return getBooleanProperty(USE_WITNESS, false);  // Disabled by default
}

public long getWitnessHeartbeatTimeout() {
    return getLongProperty(WITNESS_HEARTBEAT_TIMEOUT, 120000);  // 2 minutes
}

public long getWitnessRegistrationTimeout() {
    return getLongProperty(WITNESS_REGISTRATION_TIMEOUT, 300000);  // 5 minutes
}

public long getWitnessReconnectDelay() {
    return getLongProperty(WITNESS_RECONNECT_DELAY, 1000);  // 1 second
}

public boolean isWitnessServiceDiscovery() {
    return getBooleanProperty(WITNESS_SERVICE_DISCOVERY, true);
}
```

## 7. Testing Strategy

### 7.1 Unit Tests
```java
@Test
public void testWitnessRegistration() {
    WitnessRegistration registration = new WitnessRegistration(
        "\\\\server\\share", 
        InetAddress.getByName("192.168.1.100"),
        WitnessServiceType.FILE_SERVER_WITNESS
    );
    
    assertNotNull(registration.getRegistrationId());
    assertEquals(WitnessRegistrationState.REGISTERING, registration.getState());
    assertFalse(registration.isExpired(60000));
    
    // Test sequence numbers
    long seq1 = registration.getNextSequenceNumber();
    long seq2 = registration.getNextSequenceNumber();
    assertEquals(seq1 + 1, seq2);
}

@Test
public void testWitnessNotification() {
    WitnessNotification notification = new WitnessNotification(
        WitnessEventType.CLIENT_MOVE, "TestResource");
    
    notification.addNewIPAddress(InetAddress.getByName("192.168.1.101"));
    
    assertEquals(WitnessEventType.CLIENT_MOVE, notification.getEventType());
    assertEquals("TestResource", notification.getResourceName());
    assertEquals(1, notification.getNewIPAddresses().size());
}

@Test
public void testWitnessClientMock() throws Exception {
    // Mock witness service for testing
    MockWitnessService mockService = new MockWitnessService();
    mockService.start();
    
    try {
        WitnessClient client = new WitnessClient(mockService.getAddress(), context);
        
        CompletableFuture<WitnessRegistration> future = client.registerForNotifications(
            "\\\\test\\share",
            InetAddress.getByName("192.168.1.100"),
            new TestWitnessListener()
        );
        
        WitnessRegistration registration = future.get(5, TimeUnit.SECONDS);
        assertNotNull(registration);
        assertEquals(WitnessRegistrationState.REGISTERED, registration.getState());
        
        client.close();
    } finally {
        mockService.stop();
    }
}
```

### 7.2 Integration Tests
```java
@Test
@EnabledIfSystemProperty(named = "witness.test.enabled", matches = "true")
public void testWitnessFailover() throws Exception {
    // Requires cluster environment for testing
    CIFSContext context = getTestContext();
    context.getConfig().setProperty("jcifs.smb.client.useWitness", "true");
    
    SmbFile file = new SmbFile("smb://cluster-server/share/test.txt", context);
    file.createNewFile();
    
    // Monitor for witness notifications
    TestWitnessListener listener = new TestWitnessListener();
    
    // Simulate cluster failover (would require test environment setup)
    // ... trigger server failover ...
    
    // Verify that witness notification was received and handled
    assertTrue(listener.waitForNotification(30000));  // 30 second timeout
    
    // Verify file is still accessible after failover
    assertTrue(file.exists());
}

@Test
public void testWitnessServiceDiscovery() throws Exception {
    CIFSContext context = getTestContext();
    context.getConfig().setProperty("jcifs.smb.client.useWitness", "true");
    context.getConfig().setProperty("jcifs.smb.client.witnessServiceDiscovery", "true");
    
    SmbSession session = new SmbSession(context, transport);
    session.initializeWitnessSupport();
    
    // Should either find witness service or gracefully handle absence
    // No exception should be thrown
}

private static class TestWitnessListener implements WitnessClient.WitnessNotificationListener {
    private volatile boolean notificationReceived = false;
    private final CountDownLatch latch = new CountDownLatch(1);
    
    @Override
    public void onWitnessNotification(WitnessNotification notification) {
        notificationReceived = true;
        latch.countDown();
    }
    
    @Override
    public void onRegistrationFailed(WitnessRegistration registration, Exception error) {
        // Test implementation
    }
    
    @Override
    public void onRegistrationExpired(WitnessRegistration registration) {
        // Test implementation
    }
    
    public boolean waitForNotification(long timeoutMs) throws InterruptedException {
        return latch.await(timeoutMs, TimeUnit.MILLISECONDS);
    }
    
    public boolean isNotificationReceived() {
        return notificationReceived;
    }
}
```

## 8. Error Handling and Reliability

### 8.1 Witness Service Unavailability
```java
public class WitnessServiceErrorHandler {
    private final WitnessClient client;
    private final ScheduledExecutorService scheduler;
    private volatile boolean serviceAvailable = true;
    
    public void handleServiceUnavailable(Exception error) {
        log.warn("Witness service unavailable: {}", error.getMessage());
        serviceAvailable = false;
        
        // Schedule retry
        scheduleServiceRetry();
    }
    
    private void scheduleServiceRetry() {
        scheduler.schedule(() -> {
            try {
                // Test if service is back online
                if (testWitnessService()) {
                    serviceAvailable = true;
                    log.info("Witness service is back online");
                    
                    // Re-register for notifications
                    reregisterNotifications();
                } else {
                    // Schedule another retry
                    scheduleServiceRetry();
                }
            } catch (Exception e) {
                log.debug("Witness service retry failed", e);
                scheduleServiceRetry();
            }
        }, 30, TimeUnit.SECONDS);
    }
    
    private boolean testWitnessService() {
        // Simple connectivity test
        return client != null && client.isConnected();
    }
    
    private void reregisterNotifications() {
        // Re-register all previous registrations
        // Implementation would store registration details for recovery
    }
}
```

### 8.2 Network Partition Handling
```java
public class WitnessNetworkPartitionHandler {
    public void handleNetworkPartition() {
        log.warn("Network partition detected - witness notifications may be delayed");
        
        // Switch to more aggressive connection retry
        // Increase heartbeat frequency
        // Consider fallback mechanisms
    }
    
    public void handlePartitionRecovery() {
        log.info("Network partition recovered - resuming normal witness operations");
        
        // Restore normal operation parameters
        // Verify all registrations are still valid
    }
}
```

## 9. Performance and Optimization

### 9.1 Witness Event Batching
```java
public class WitnessEventBatcher {
    private final Queue<WitnessNotification> pendingNotifications;
    private final ScheduledExecutorService scheduler;
    private final int batchSize = 10;
    private final long batchTimeout = 100;  // 100ms
    
    public void addNotification(WitnessNotification notification) {
        synchronized (pendingNotifications) {
            pendingNotifications.offer(notification);
            
            if (pendingNotifications.size() >= batchSize) {
                processBatch();
            }
        }
    }
    
    private void processBatch() {
        List<WitnessNotification> batch = new ArrayList<>();
        
        synchronized (pendingNotifications) {
            while (!pendingNotifications.isEmpty() && batch.size() < batchSize) {
                batch.add(pendingNotifications.poll());
            }
        }
        
        if (!batch.isEmpty()) {
            processNotificationBatch(batch);
        }
    }
    
    private void processNotificationBatch(List<WitnessNotification> notifications) {
        // Process multiple notifications together for efficiency
        for (WitnessNotification notification : notifications) {
            // Handle notification
        }
    }
}
```

## 10. Security Considerations

### 10.1 Witness Authentication
```java
public class WitnessSecurityManager {
    public void authenticateWitnessService(InetAddress witnessServer) throws SecurityException {
        // Verify witness service is authorized
        if (!isAuthorizedWitnessServer(witnessServer)) {
            throw new SecurityException("Unauthorized witness server: " + witnessServer);
        }
    }
    
    public void validateNotification(WitnessNotification notification) throws SecurityException {
        // Validate notification authenticity
        if (!isValidNotificationSource(notification)) {
            throw new SecurityException("Invalid witness notification source");
        }
    }
    
    private boolean isAuthorizedWitnessServer(InetAddress server) {
        // Implementation would check against authorized server list
        // Could use certificates, Kerberos, etc.
        return true;  // Simplified
    }
    
    private boolean isValidNotificationSource(WitnessNotification notification) {
        // Validate notification signature/source
        return true;  // Simplified
    }
}
```

## 11. Monitoring and Metrics

### 11.1 Witness Statistics
```java
public class WitnessStatistics {
    private final AtomicLong registrationsActive = new AtomicLong();
    private final AtomicLong notificationsReceived = new AtomicLong();
    private final AtomicLong failoverEvents = new AtomicLong();
    private final AtomicLong heartbeatsSent = new AtomicLong();
    private final AtomicLong registrationFailures = new AtomicLong();
    
    public void recordRegistration() { registrationsActive.incrementAndGet(); }
    public void recordUnregistration() { registrationsActive.decrementAndGet(); }
    public void recordNotification() { notificationsReceived.incrementAndGet(); }
    public void recordFailover() { failoverEvents.incrementAndGet(); }
    public void recordHeartbeat() { heartbeatsSent.incrementAndGet(); }
    public void recordRegistrationFailure() { registrationFailures.incrementAndGet(); }
    
    // Getters for all statistics...
    public long getActiveRegistrations() { return registrationsActive.get(); }
    public long getNotificationsReceived() { return notificationsReceived.get(); }
    public long getFailoverEvents() { return failoverEvents.get(); }
}