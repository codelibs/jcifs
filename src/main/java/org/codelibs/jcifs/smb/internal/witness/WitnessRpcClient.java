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
import java.util.List;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.dcerpc.DcerpcHandle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Client implementation for the SMB Witness RPC protocol (MS-SWN).
 * Provides communication with witness servers for monitoring SMB resource availability.
 */
public class WitnessRpcClient implements AutoCloseable {
    private static final Logger log = LoggerFactory.getLogger(WitnessRpcClient.class);

    private final InetAddress serverAddress;
    private final CIFSContext context;
    private volatile boolean connected = false;
    private DcerpcHandle rpcHandle;

    // Witness RPC interface
    private static final String WITNESS_INTERFACE_UUID = "ccd8c074-d0e5-4a40-92b4-d074faa6ba28";
    private static final int WITNESS_INTERFACE_VERSION = 1;

    // RPC connection parameters
    private static final int WITNESS_RPC_PORT = 135;
    private static final int WITNESS_RPC_TIMEOUT_MS = 5000;

    // RPC operation numbers
    private static final int WITNESS_REGISTER = 0;
    private static final int WITNESS_UNREGISTER = 1;
    private static final int WITNESS_ASYNC_NOTIFY = 2;
    private static final int WITNESS_HEARTBEAT = 3;

    /**
     * Creates a new witness RPC client.
     *
     * @param serverAddress the witness server address
     * @param context the CIFS context
     * @throws IOException if connection fails
     */
    public WitnessRpcClient(InetAddress serverAddress, CIFSContext context) throws IOException {
        this.serverAddress = serverAddress;
        this.context = context;

        try {
            // Create DCE/RPC handle for witness service
            String rpcUrl = buildWitnessRpcUrl(serverAddress);
            this.rpcHandle = DcerpcHandle.getHandle(rpcUrl, context);
            this.rpcHandle.bind();
            this.connected = true;

            log.debug("Connected to witness service at {}", serverAddress.getHostAddress());
        } catch (Exception e) {
            throw new IOException("Failed to connect to witness service", e);
        }
    }

    /**
     * Builds the RPC URL for the witness service.
     *
     * @param serverAddress the server address
     * @return the RPC URL
     */
    private String buildWitnessRpcUrl(InetAddress serverAddress) {
        // DCE/RPC over named pipes: ncacn_np:\\server[\pipe\witness]
        return "ncacn_np:\\\\" + serverAddress.getHostAddress() + "[\\pipe\\witness]";
    }

    /**
     * Tests connectivity to the witness service.
     *
     * @throws IOException if connection fails
     */
    private void testConnection() throws IOException {
        // For now, just test basic connectivity to RPC endpoint
        try (java.net.Socket socket = new java.net.Socket()) {
            socket.connect(new java.net.InetSocketAddress(serverAddress, WITNESS_RPC_PORT), WITNESS_RPC_TIMEOUT_MS);
        } catch (IOException e) {
            throw new IOException("Cannot connect to RPC endpoint at " + serverAddress.getHostAddress() + ":" + WITNESS_RPC_PORT, e);
        }
    }

    /**
     * Performs witness registration.
     *
     * @param request the registration request
     * @return the registration response
     * @throws IOException if the RPC call fails
     */
    public WitnessRegisterResponse register(WitnessRegisterRequest request) throws IOException {
        if (!connected) {
            throw new IOException("Witness client not connected");
        }

        try {
            log.debug("Registering witness for share: {}", request.getShareName());

            // Create and populate the RPC message
            WitnessRegisterMessage message = new WitnessRegisterMessage();
            // Convert int version to WitnessVersion enum
            WitnessVersion witnessVersion = (request.getVersion() >= 0x00020000) ? WitnessVersion.VERSION_2 : WitnessVersion.VERSION_1;
            message.setVersion(witnessVersion);
            message.setNetName(serverAddress.getHostName());
            message.setShareName(request.getShareName());
            message.setIpAddress(request.getServerAddress());
            message.setClientComputerName(context.getConfig().getNetbiosHostname());
            message.setFlags(request.getFlags());
            message.setTimeout((int) (context.getConfig().getWitnessRegistrationTimeout() / 1000));

            // Send the RPC request
            rpcHandle.sendrecv(message);

            // Create response from RPC message results
            WitnessRegisterResponse response = new WitnessRegisterResponse();
            response.setReturnCode(message.getReturnCode());

            if (message.isSuccess()) {
                // Generate registration ID from context handle
                byte[] contextHandle = message.getContextHandle();
                String registrationId = generateRegistrationId(contextHandle, request.getShareName());
                response.setRegistrationId(registrationId);
                response.setContextHandle(contextHandle);

                log.debug("Witness registration successful: {}", registrationId);
            } else {
                response.setError(message.getErrorMessage());
                log.warn("Witness registration failed: {}", message.getErrorMessage());
            }

            return response;

        } catch (Exception e) {
            throw new IOException("Witness register RPC failed", e);
        }
    }

    /**
     * Performs witness unregistration.
     *
     * @param request the unregistration request
     * @return the unregistration response
     * @throws IOException if the RPC call fails
     */
    public WitnessUnregisterResponse unregister(WitnessUnregisterRequest request) throws IOException {
        if (!connected) {
            throw new IOException("Witness client not connected");
        }

        try {
            log.debug("Unregistering witness: {}", request.getRegistrationId());

            // Create and populate the RPC message
            WitnessUnregisterMessage message = new WitnessUnregisterMessage();
            message.setContextHandle(request.getContextHandle());

            // Send the RPC request
            rpcHandle.sendrecv(message);

            // Create response from RPC message results
            WitnessUnregisterResponse response = new WitnessUnregisterResponse();
            response.setReturnCode(message.getReturnCode());

            if (message.isSuccess()) {
                log.debug("Witness unregistration successful");
            } else {
                response.setError(message.getErrorMessage());
                log.warn("Witness unregistration failed: {}", message.getErrorMessage());
            }

            return response;

        } catch (Exception e) {
            throw new IOException("Witness unregister RPC failed", e);
        }
    }

    /**
     * Sends a witness heartbeat.
     *
     * @param request the heartbeat request
     * @return the heartbeat response
     * @throws IOException if the RPC call fails
     */
    public WitnessHeartbeatResponse heartbeat(WitnessHeartbeatRequest request) throws IOException {
        if (!connected) {
            throw new IOException("Witness client not connected");
        }

        try {
            log.debug("Sending witness heartbeat for: {}", request.getRegistrationId());

            // Create and populate the RPC message
            WitnessHeartbeatMessage message = new WitnessHeartbeatMessage();
            message.setContextHandle(request.getContextHandle());
            message.setSequenceNumber(request.getSequenceNumber());

            // Send the RPC request
            rpcHandle.sendrecv(message);

            // Create response from RPC message results
            WitnessHeartbeatResponse response = new WitnessHeartbeatResponse();
            response.setReturnCode(message.getReturnCode());
            response.setSequenceNumber(message.getResponseSequenceNumber());

            if (message.isSuccess()) {
                // Set recommended heartbeat interval from server
                response.setRecommendedHeartbeatInterval(message.getHeartbeatInterval());
                log.debug("Witness heartbeat successful, next interval: {} ms", message.getHeartbeatInterval());
            } else {
                response.setError(message.getErrorMessage());
                log.warn("Witness heartbeat failed: {}", message.getErrorMessage());
            }

            return response;

        } catch (Exception e) {
            throw new IOException("Witness heartbeat RPC failed", e);
        }
    }

    /**
     * Requests asynchronous notifications from the witness service.
     *
     * @param contextHandle the context handle from registration
     * @return the async notify response containing notifications
     * @throws IOException if the RPC call fails
     */
    public WitnessAsyncNotifyMessage.WitnessNotificationResponse getAsyncNotifications(byte[] contextHandle) throws IOException {
        if (!connected) {
            throw new IOException("Witness client not connected");
        }

        try {
            log.debug("Requesting async notifications");

            // Create and populate the RPC message
            WitnessAsyncNotifyMessage message = new WitnessAsyncNotifyMessage();
            message.setContextHandle(contextHandle);

            // Send the RPC request
            rpcHandle.sendrecv(message);

            if (message.isSuccess()) {
                List<WitnessAsyncNotifyMessage.WitnessNotificationResponse> notifications = message.getNotifications();
                if (!notifications.isEmpty()) {
                    log.debug("Received {} notifications", notifications.size());
                    return notifications.get(0); // Return first notification
                }
            } else {
                log.warn("Async notify failed: {}", message.getErrorMessage());
            }

            return null;

        } catch (Exception e) {
            throw new IOException("Witness async notify RPC failed", e);
        }
    }

    /**
     * Generates a registration ID from context handle and share name.
     *
     * @param contextHandle the context handle
     * @param shareName the share name
     * @return the registration ID
     */
    private String generateRegistrationId(byte[] contextHandle, String shareName) {
        if (contextHandle == null || contextHandle.length == 0) {
            return "WITNESS-" + System.currentTimeMillis() + "-" + shareName.hashCode();
        }

        // Use context handle bytes to create a unique ID
        StringBuilder sb = new StringBuilder("WITNESS-");
        for (int i = 0; i < Math.min(contextHandle.length, 8); i++) {
            sb.append(String.format("%02X", contextHandle[i] & 0xFF));
        }
        sb.append("-").append(shareName.hashCode());

        return sb.toString();
    }

    /**
     * Checks if the client is connected to the witness service.
     *
     * @return true if connected
     */
    public boolean isConnected() {
        return connected && rpcHandle != null;
    }

    @Override
    public void close() {
        if (connected && rpcHandle != null) {
            try {
                log.debug("Closing witness RPC client");
                rpcHandle.close();
                connected = false;
                rpcHandle = null;
            } catch (Exception e) {
                log.error("Error closing witness RPC client", e);
            }
        }
    }
}