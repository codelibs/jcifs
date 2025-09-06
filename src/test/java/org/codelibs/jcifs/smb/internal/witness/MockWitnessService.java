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
package org.codelibs.jcifs.smb.internal.witness;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Mock witness service for integration testing.
 * Simulates a basic witness service that can accept registrations
 * and send notifications.
 */
public class MockWitnessService implements AutoCloseable {
    private static final Logger log = LoggerFactory.getLogger(MockWitnessService.class);

    private ServerSocket serverSocket;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicInteger registrationCounter = new AtomicInteger(0);
    private final ConcurrentHashMap<String, MockRegistration> registrations = new ConcurrentHashMap<>();
    private Thread serverThread;

    /**
     * Mock registration data
     */
    private static class MockRegistration {
        final String registrationId;
        final String shareName;
        final String serverAddress;
        final int flags;
        final long timestamp;

        MockRegistration(String registrationId, String shareName, String serverAddress, int flags) {
            this.registrationId = registrationId;
            this.shareName = shareName;
            this.serverAddress = serverAddress;
            this.flags = flags;
            this.timestamp = System.currentTimeMillis();
        }
    }

    /**
     * Start the mock witness service
     *
     * @throws IOException if service startup fails
     */
    public void start() throws IOException {
        serverSocket = new ServerSocket(0); // Use any available port
        running.set(true);

        serverThread = new Thread(this::runServer, "MockWitnessService");
        serverThread.setDaemon(true);
        serverThread.start();

        log.info("Mock witness service started on port {}", serverSocket.getLocalPort());
    }

    /**
     * Stop the mock witness service
     */
    public void stop() {
        running.set(false);

        if (serverSocket != null && !serverSocket.isClosed()) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                log.debug("Error closing server socket", e);
            }
        }

        if (serverThread != null) {
            try {
                serverThread.join(5000); // Wait up to 5 seconds
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        registrations.clear();
        log.info("Mock witness service stopped");
    }

    /**
     * Get the address the service is listening on
     *
     * @return the service address
     * @throws IOException if address cannot be determined
     */
    public InetAddress getAddress() throws IOException {
        if (serverSocket == null) {
            throw new IOException("Service not started");
        }
        return InetAddress.getLocalHost();
    }

    /**
     * Get the port the service is listening on
     *
     * @return the service port
     * @throws IOException if port cannot be determined
     */
    public int getPort() throws IOException {
        if (serverSocket == null) {
            throw new IOException("Service not started");
        }
        return serverSocket.getLocalPort();
    }

    /**
     * Simulate a witness registration
     *
     * @param shareName the share name
     * @param serverAddress the server address
     * @param flags the registration flags
     * @return the registration ID
     */
    public String registerWitness(String shareName, String serverAddress, int flags) {
        String registrationId = "MOCK-REG-" + registrationCounter.incrementAndGet();
        MockRegistration registration = new MockRegistration(registrationId, shareName, serverAddress, flags);
        registrations.put(registrationId, registration);

        log.debug("Mock registered witness: {} for share: {}", registrationId, shareName);
        return registrationId;
    }

    /**
     * Simulate a witness unregistration
     *
     * @param registrationId the registration ID to remove
     * @return true if registration was found and removed
     */
    public boolean unregisterWitness(String registrationId) {
        MockRegistration removed = registrations.remove(registrationId);
        if (removed != null) {
            log.debug("Mock unregistered witness: {}", registrationId);
            return true;
        }
        return false;
    }

    /**
     * Get the number of active registrations
     *
     * @return the registration count
     */
    public int getRegistrationCount() {
        return registrations.size();
    }

    /**
     * Check if a registration exists
     *
     * @param registrationId the registration ID
     * @return true if registration exists
     */
    public boolean hasRegistration(String registrationId) {
        return registrations.containsKey(registrationId);
    }

    /**
     * Simulate sending a witness notification
     *
     * @param eventType the event type
     * @param resourceName the resource name
     */
    public void sendNotification(WitnessEventType eventType, String resourceName) {
        // In a real implementation, this would send notifications to registered clients
        // For the mock, we just log it
        log.info("Mock sending notification: {} for resource: {}", eventType, resourceName);

        // Count how many registrations this affects
        int affectedRegistrations = 0;
        for (MockRegistration reg : registrations.values()) {
            if (reg.shareName.equalsIgnoreCase(resourceName) || reg.serverAddress.equals(resourceName)) {
                affectedRegistrations++;
            }
        }

        log.debug("Notification affects {} registrations", affectedRegistrations);
    }

    /**
     * Main server loop - simplified implementation
     */
    private void runServer() {
        while (running.get() && !serverSocket.isClosed()) {
            try {
                Socket clientSocket = serverSocket.accept();
                // In a real implementation, this would handle RPC requests
                // For the mock, we just accept connections and close them
                clientSocket.close();
            } catch (IOException e) {
                if (running.get()) {
                    log.debug("Error accepting client connection", e);
                }
            }
        }
    }

    @Override
    public void close() {
        stop();
    }

    /**
     * Helper method to create a complete mock service address
     *
     * @return formatted address string for RPC connections
     */
    public String getServiceAddress() {
        try {
            return "ncacn_ip_tcp:" + getAddress().getHostAddress() + "[" + getPort() + "]";
        } catch (IOException e) {
            return "ncacn_ip_tcp:127.0.0.1[135]";
        }
    }

    /**
     * Simulate heartbeat processing
     *
     * @param registrationId the registration ID
     * @param sequenceNumber the sequence number
     * @return true if heartbeat was successful
     */
    public boolean processHeartbeat(String registrationId, long sequenceNumber) {
        MockRegistration registration = registrations.get(registrationId);
        if (registration != null) {
            log.debug("Mock processed heartbeat for: {} seq: {}", registrationId, sequenceNumber);
            return true;
        }
        return false;
    }
}
