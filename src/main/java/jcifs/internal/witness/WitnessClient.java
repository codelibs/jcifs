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
package jcifs.internal.witness;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.internal.witness.WitnessRegistration.WitnessRegistrationState;

/**
 * SMB Witness Protocol client implementation as defined in MS-SWN specification.
 * Manages witness registrations, notifications, and heartbeats for cluster failover support.
 */
public class WitnessClient implements AutoCloseable {
    private static final Logger log = LoggerFactory.getLogger(WitnessClient.class);

    private final InetAddress witnessServer;
    private final int port;
    private final CIFSContext context;
    private final ConcurrentHashMap<String, WitnessRegistration> registrations;
    private final ConcurrentHashMap<String, WitnessNotificationListener> listeners;
    private final ScheduledExecutorService scheduler;
    private final WitnessRpcClient rpcClient;

    // Witness service endpoint
    private static final String WITNESS_SERVICE_UUID = "ccd8c074-d0e5-4a40-92b4-d074faa6ba28";
    private static final int DEFAULT_WITNESS_PORT = 135; // RPC endpoint mapper

    /**
     * Interface for receiving witness notifications and registration events.
     */
    public interface WitnessNotificationListener {
        /**
         * Called when a witness notification is received.
         *
         * @param notification the witness notification
         */
        void onWitnessNotification(WitnessNotification notification);

        /**
         * Called when a witness registration fails.
         *
         * @param registration the failed registration
         * @param error the error that occurred
         */
        void onRegistrationFailed(WitnessRegistration registration, Exception error);

        /**
         * Called when a witness registration expires.
         *
         * @param registration the expired registration
         */
        void onRegistrationExpired(WitnessRegistration registration);
    }

    /**
     * Creates a new witness client.
     *
     * @param witnessServer the witness server address
     * @param context the CIFS context
     * @throws IOException if initialization fails
     */
    public WitnessClient(InetAddress witnessServer, CIFSContext context) throws IOException {
        this(witnessServer, context, new WitnessRpcClient(witnessServer, context));
    }

    /**
     * Creates a new witness client with a custom RPC client (for testing).
     *
     * @param witnessServer the witness server address
     * @param context the CIFS context
     * @param rpcClient the RPC client to use
     */
    protected WitnessClient(InetAddress witnessServer, CIFSContext context, WitnessRpcClient rpcClient) {
        this.witnessServer = witnessServer;
        this.port = DEFAULT_WITNESS_PORT;
        this.context = context;
        this.registrations = new ConcurrentHashMap<>();
        this.listeners = new ConcurrentHashMap<>();
        this.scheduler = Executors.newScheduledThreadPool(2);
        this.rpcClient = rpcClient;

        // Schedule periodic tasks
        schedulePeriodicTasks();
    }

    /**
     * Schedules periodic tasks for heartbeat and registration monitoring.
     */
    private void schedulePeriodicTasks() {
        // Heartbeat monitoring
        scheduler.scheduleAtFixedRate(this::checkHeartbeats, 30, 30, TimeUnit.SECONDS);

        // Registration monitoring
        scheduler.scheduleAtFixedRate(this::monitorRegistrations, 10, 10, TimeUnit.SECONDS);
    }

    /**
     * Registers for witness notifications.
     *
     * @param shareName the share name to monitor
     * @param serverAddress the server address
     * @param listener the notification listener
     * @return a future that completes with the registration
     */
    public CompletableFuture<WitnessRegistration> registerForNotifications(String shareName, InetAddress serverAddress,
            WitnessNotificationListener listener) {

        return CompletableFuture.supplyAsync(() -> {
            try {
                // Create registration
                WitnessRegistration registration =
                        new WitnessRegistration(shareName, serverAddress, WitnessServiceType.FILE_SERVER_WITNESS);

                // Perform RPC registration
                WitnessRegisterRequest request = new WitnessRegisterRequest();
                request.setVersion(registration.getVersion().getValue());
                request.setShareName(shareName);
                request.setServerAddress(serverAddress.getHostAddress());
                request.setFlags(registration.getFlags());

                WitnessRegisterResponse response = rpcClient.register(request);

                if (response != null && response.isSuccess()) {
                    registration.setState(WitnessRegistrationState.REGISTERED);
                    registrations.put(registration.getRegistrationId(), registration);
                    listeners.put(registration.getRegistrationId(), listener);

                    log.info("Successfully registered for witness notifications: {}", registration.getRegistrationId());

                    return registration;
                } else {
                    String errorMsg = response != null ? response.getError() : "Response was null";
                    throw new IOException("Witness registration failed: " + errorMsg);
                }

            } catch (Exception e) {
                log.error("Failed to register for witness notifications", e);
                throw new RuntimeException(e);
            }
        });
    }

    /**
     * Unregisters from witness notifications.
     *
     * @param registration the registration to remove
     * @return a future that completes when unregistration is done
     */
    public CompletableFuture<Void> unregister(WitnessRegistration registration) {
        return CompletableFuture.runAsync(() -> {
            try {
                registration.setState(WitnessRegistrationState.UNREGISTERING);

                WitnessUnregisterRequest request = new WitnessUnregisterRequest();
                request.setRegistrationId(registration.getRegistrationId());

                WitnessUnregisterResponse response = rpcClient.unregister(request);

                if (response != null && response.isSuccess()) {
                    registrations.remove(registration.getRegistrationId());
                    listeners.remove(registration.getRegistrationId());

                    log.info("Successfully unregistered witness: {}", registration.getRegistrationId());
                } else {
                    String errorMsg = response != null ? response.getError() : "Response was null";
                    log.warn("Failed to unregister witness: {}", errorMsg);
                }

            } catch (Exception e) {
                log.error("Error during witness unregistration", e);
            }
        });
    }

    /**
     * Processes a received witness notification.
     *
     * @param notification the notification to process
     */
    public void processNotification(WitnessNotification notification) {
        log.info("Received witness notification: {} for resource: {}", notification.getEventType(), notification.getResourceName());

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

    /**
     * Determines if a notification should be delivered to a registration.
     *
     * @param registration the registration
     * @param notification the notification
     * @return true if the notification should be delivered
     */
    private boolean shouldDeliverNotification(WitnessRegistration registration, WitnessNotification notification) {
        // Check if notification is relevant to this registration
        String resourceName = notification.getResourceName();
        String shareName = registration.getShareName();

        // Match by share name or server address
        return resourceName.equalsIgnoreCase(shareName) || resourceName.equals(registration.getServerAddress().getHostAddress());
    }

    /**
     * Checks for expired registrations based on heartbeat timeouts.
     */
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

    /**
     * Monitors active registrations and sends heartbeats.
     */
    private void monitorRegistrations() {
        for (WitnessRegistration registration : registrations.values()) {
            if (registration.getState() == WitnessRegistrationState.REGISTERED) {
                // Send periodic heartbeat
                sendHeartbeat(registration);
            }
        }
    }

    /**
     * Sends a heartbeat for the specified registration.
     *
     * @param registration the registration
     */
    private void sendHeartbeat(WitnessRegistration registration) {
        try {
            WitnessHeartbeatRequest request = new WitnessHeartbeatRequest();
            request.setRegistrationId(registration.getRegistrationId());
            request.setSequenceNumber(registration.getNextSequenceNumber());

            WitnessHeartbeatResponse response = rpcClient.heartbeat(request);

            if (response != null && response.isSuccess()) {
                registration.updateHeartbeat();
            } else {
                log.warn("Witness heartbeat failed for: {}", registration.getRegistrationId());
            }

        } catch (Exception e) {
            log.debug("Heartbeat error for registration: {}", registration.getRegistrationId(), e);
        }
    }

    /**
     * Gets the witness server address.
     *
     * @return the witness server address
     */
    public InetAddress getWitnessServer() {
        return witnessServer;
    }

    /**
     * Gets the number of active registrations.
     *
     * @return the number of active registrations
     */
    public int getActiveRegistrationCount() {
        return registrations.size();
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
            CompletableFuture.allOf(unregisterFutures.toArray(new CompletableFuture[0])).get(10, TimeUnit.SECONDS);
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
