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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrException;

/**
 * WitnessAsyncNotify RPC message implementation for MS-SWN specification.
 * This message is used to receive asynchronous notifications from the witness service.
 */
public class WitnessAsyncNotifyMessage extends WitnessRpcMessage {

    // Input parameters for WitnessAsyncNotify
    private byte[] contextHandle;

    // Output parameters for WitnessAsyncNotify
    private List<WitnessNotificationResponse> notifications;

    /**
     * Creates a new WitnessAsyncNotify RPC message.
     */
    public WitnessAsyncNotifyMessage() {
        super(WITNESS_ASYNC_NOTIFY);
        this.contextHandle = new byte[20];
        this.notifications = new ArrayList<>();
    }

    /**
     * Creates a new WitnessAsyncNotify RPC message with the specified context handle.
     *
     * @param contextHandle the context handle from registration
     */
    public WitnessAsyncNotifyMessage(byte[] contextHandle) {
        super(WITNESS_ASYNC_NOTIFY);
        this.contextHandle = contextHandle != null ? contextHandle.clone() : new byte[20];
        this.notifications = new ArrayList<>();
    }

    /**
     * Sets the context handle for the async notify request.
     *
     * @param contextHandle the context handle from registration
     */
    public void setContextHandle(byte[] contextHandle) {
        this.contextHandle = contextHandle != null ? contextHandle.clone() : null;
    }

    /**
     * Gets the context handle.
     *
     * @return the context handle
     */
    public byte[] getContextHandle() {
        return contextHandle != null ? contextHandle.clone() : null;
    }

    /**
     * Gets the list of notifications received.
     *
     * @return the list of notifications
     */
    public List<WitnessNotificationResponse> getNotifications() {
        return new ArrayList<>(notifications);
    }

    /**
     * Sets the notifications list.
     *
     * @param notifications the notifications to set
     */
    public void setNotifications(List<WitnessNotificationResponse> notifications) {
        this.notifications = notifications != null ? new ArrayList<>(notifications) : new ArrayList<>();
    }

    @Override
    protected void encodeWitnessParameters(NdrBuffer buf) throws NdrException {
        // Encode input parameters for WitnessAsyncNotify

        // Context handle (20 bytes)
        if (contextHandle != null) {
            buf.writeOctetArray(contextHandle, 0, Math.min(contextHandle.length, 20));
            // Pad with zeros if context handle is shorter than 20 bytes
            for (int i = contextHandle.length; i < 20; i++) {
                buf.enc_ndr_small(0);
            }
        } else {
            // Write 20 zero bytes for null context handle
            for (int i = 0; i < 20; i++) {
                buf.enc_ndr_small(0);
            }
        }
    }

    @Override
    protected void decodeWitnessParameters(NdrBuffer buf) throws NdrException {
        // Decode output parameters for WitnessAsyncNotify

        // Response buffer size
        int responseLength = buf.dec_ndr_long();

        if (responseLength > 0) {
            // Decode notification array
            int notificationCount = buf.dec_ndr_long();
            notifications = new ArrayList<>(notificationCount);

            for (int i = 0; i < notificationCount; i++) {
                WitnessNotificationResponse notification = decodeNotification(buf);
                notifications.add(notification);
            }
        }
    }

    /**
     * Decodes a single notification from the NDR buffer.
     *
     * @param buf the NDR buffer
     * @return the decoded notification
     * @throws NdrException if decoding fails
     */
    private WitnessNotificationResponse decodeNotification(NdrBuffer buf) throws NdrException {
        WitnessNotificationResponse notification = new WitnessNotificationResponse();

        // Notification type
        int notificationType = buf.dec_ndr_long();
        notification.setNotificationType(WitnessEventType.fromValue(notificationType));

        // Length
        int length = buf.dec_ndr_long();
        notification.setLength(length);

        // Number of messages
        int numberOfMessages = buf.dec_ndr_long();

        // Messages array
        List<WitnessNotificationMessage> messages = new ArrayList<>(numberOfMessages);
        for (int i = 0; i < numberOfMessages; i++) {
            WitnessNotificationMessage message = decodeNotificationMessage(buf);
            messages.add(message);
        }
        notification.setMessages(messages);

        return notification;
    }

    /**
     * Decodes a single notification message from the NDR buffer.
     *
     * @param buf the NDR buffer
     * @return the decoded notification message
     * @throws NdrException if decoding fails
     */
    private WitnessNotificationMessage decodeNotificationMessage(NdrBuffer buf) throws NdrException {
        WitnessNotificationMessage message = new WitnessNotificationMessage();

        // Message type
        int messageType = buf.dec_ndr_long();
        message.setType(messageType);

        // Message length
        int messageLength = buf.dec_ndr_long();
        message.setLength(messageLength);

        // Based on message type, decode specific data
        switch (messageType) {
        case WitnessNotificationMessage.WITNESS_RESOURCE_CHANGE:
            decodeResourceChangeMessage(buf, message);
            break;
        case WitnessNotificationMessage.WITNESS_CLIENT_MOVE:
            decodeClientMoveMessage(buf, message);
            break;
        case WitnessNotificationMessage.WITNESS_SHARE_MOVE:
            decodeShareMoveMessage(buf, message);
            break;
        case WitnessNotificationMessage.WITNESS_IP_CHANGE:
            decodeIpChangeMessage(buf, message);
            break;
        default:
            // Skip unknown message types
            buf.advance(messageLength - 8); // Skip remaining data (minus type and length)
            break;
        }

        return message;
    }

    /**
     * Decodes a resource change notification message.
     */
    private void decodeResourceChangeMessage(NdrBuffer buf, WitnessNotificationMessage message) throws NdrException {
        // Timestamp (FILETIME - 64-bit)
        long timestamp = buf.dec_ndr_hyper();
        message.setTimestamp(timestamp);

        // Resource name
        String resourceName = decodeWideStringPointer(buf);
        message.setResourceName(resourceName);
    }

    /**
     * Decodes a client move notification message.
     */
    private void decodeClientMoveMessage(NdrBuffer buf, WitnessNotificationMessage message) throws NdrException {
        // Timestamp
        long timestamp = buf.dec_ndr_hyper();
        message.setTimestamp(timestamp);

        // Destination node
        String destinationNode = decodeWideStringPointer(buf);
        message.setDestinationNode(destinationNode);
    }

    /**
     * Decodes a share move notification message.
     */
    private void decodeShareMoveMessage(NdrBuffer buf, WitnessNotificationMessage message) throws NdrException {
        // Timestamp
        long timestamp = buf.dec_ndr_hyper();
        message.setTimestamp(timestamp);

        // Source node
        String sourceNode = decodeWideStringPointer(buf);
        message.setSourceNode(sourceNode);

        // Destination node
        String destinationNode = decodeWideStringPointer(buf);
        message.setDestinationNode(destinationNode);
    }

    /**
     * Decodes an IP change notification message.
     */
    private void decodeIpChangeMessage(NdrBuffer buf, WitnessNotificationMessage message) throws NdrException {
        // Timestamp
        long timestamp = buf.dec_ndr_hyper();
        message.setTimestamp(timestamp);

        // Number of IP addresses
        int ipCount = buf.dec_ndr_long();
        List<String> ipAddresses = new ArrayList<>(ipCount);

        for (int i = 0; i < ipCount; i++) {
            String ipAddress = decodeWideStringPointer(buf);
            ipAddresses.add(ipAddress);
        }
        message.setIpAddresses(ipAddresses);
    }

    /**
     * Decodes a wide string pointer from NDR format.
     */
    private String decodeWideStringPointer(NdrBuffer buf) throws NdrException {
        int pointer = buf.dec_ndr_long();
        if (pointer == 0) {
            return null; // NULL pointer
        }

        int maxCount = buf.dec_ndr_long();
        int offset = buf.dec_ndr_long();
        int actualCount = buf.dec_ndr_long();

        if (actualCount <= 0) {
            return "";
        }

        // Read wide string data (UTF-16LE)
        int byteCount = (actualCount - 1) * 2; // Exclude null terminator
        byte[] wideBytes = new byte[byteCount];
        buf.readOctetArray(wideBytes, 0, byteCount);

        // Skip null terminator
        buf.dec_ndr_short();

        // Skip padding
        int padding = (4 - ((byteCount + 2) % 4)) % 4;
        for (int i = 0; i < padding; i++) {
            buf.dec_ndr_small();
        }

        return new String(wideBytes, StandardCharsets.UTF_16LE);
    }

    /**
     * Response structure for witness notifications.
     * Contains the notification type and associated messages from the witness service.
     */
    public static class WitnessNotificationResponse {
        /**
         * Creates a new witness notification response.
         */
        public WitnessNotificationResponse() {
            // Default constructor
        }

        private WitnessEventType notificationType;
        private int length;
        private List<WitnessNotificationMessage> messages;

        /**
         * Gets the notification type.
         *
         * @return the witness event type for this notification
         */
        public WitnessEventType getNotificationType() {
            return notificationType;
        }

        /**
         * Sets the notification type.
         *
         * @param notificationType the witness event type for this notification
         */
        public void setNotificationType(WitnessEventType notificationType) {
            this.notificationType = notificationType;
        }

        /**
         * Gets the total length of the notification response.
         *
         * @return the length in bytes of the entire notification response
         */
        public int getLength() {
            return length;
        }

        /**
         * Sets the total length of the notification response.
         *
         * @param length the length in bytes of the entire notification response
         */
        public void setLength(int length) {
            this.length = length;
        }

        /**
         * Gets the list of notification messages.
         *
         * @return the list of individual notification messages contained in this response
         */
        public List<WitnessNotificationMessage> getMessages() {
            return messages;
        }

        /**
         * Sets the list of notification messages.
         *
         * @param messages the list of individual notification messages contained in this response
         */
        public void setMessages(List<WitnessNotificationMessage> messages) {
            this.messages = messages;
        }
    }

    /**
     * Individual notification message within a notification response.
     */
    public static class WitnessNotificationMessage {

        /**
         * Creates a new witness notification message
         */
        public WitnessNotificationMessage() {
            // Default constructor
        }

        // Message types from MS-SWN specification
        /** Witness resource change notification type */
        public static final int WITNESS_RESOURCE_CHANGE = 1;
        /** Witness client move notification type */
        public static final int WITNESS_CLIENT_MOVE = 2;
        /** Witness share move notification type */
        public static final int WITNESS_SHARE_MOVE = 3;
        /** Witness IP address change notification type */
        public static final int WITNESS_IP_CHANGE = 4;

        private int type;
        private int length;
        private long timestamp;
        private String resourceName;
        private String sourceNode;
        private String destinationNode;
        private List<String> ipAddresses;

        /**
         * Get the notification message type
         *
         * @return message type
         */
        public int getType() {
            return type;
        }

        /**
         * Sets the notification message type.
         *
         * @param type the message type (WITNESS_RESOURCE_CHANGE, WITNESS_CLIENT_MOVE, WITNESS_SHARE_MOVE, or WITNESS_IP_CHANGE)
         */
        public void setType(int type) {
            this.type = type;
        }

        /**
         * Get the notification message length
         *
         * @return message length in bytes
         */
        public int getLength() {
            return length;
        }

        /**
         * Sets the notification message length.
         *
         * @param length the message length in bytes
         */
        public void setLength(int length) {
            this.length = length;
        }

        /**
         * Get the notification timestamp
         *
         * @return timestamp in milliseconds
         */
        public long getTimestamp() {
            return timestamp;
        }

        /**
         * Sets the notification timestamp.
         *
         * @param timestamp the timestamp value in FILETIME format (100-nanosecond intervals since January 1, 1601 UTC)
         */
        public void setTimestamp(long timestamp) {
            this.timestamp = timestamp;
        }

        /**
         * Get the resource name associated with the notification
         *
         * @return resource name
         */
        public String getResourceName() {
            return resourceName;
        }

        /**
         * Sets the resource name associated with the notification.
         *
         * @param resourceName the name of the resource affected by the change
         */
        public void setResourceName(String resourceName) {
            this.resourceName = resourceName;
        }

        /**
         * Get the source node for move operations
         *
         * @return source node name
         */
        public String getSourceNode() {
            return sourceNode;
        }

        /**
         * Sets the source node for move operations.
         *
         * @param sourceNode the name of the source node in a share move operation
         */
        public void setSourceNode(String sourceNode) {
            this.sourceNode = sourceNode;
        }

        /**
         * Get the destination node for move operations
         *
         * @return destination node name
         */
        public String getDestinationNode() {
            return destinationNode;
        }

        /**
         * Sets the destination node for move operations.
         *
         * @param destinationNode the name of the destination node in a client or share move operation
         */
        public void setDestinationNode(String destinationNode) {
            this.destinationNode = destinationNode;
        }

        /**
         * Get the list of IP addresses for IP change notifications
         *
         * @return list of IP addresses
         */
        public List<String> getIpAddresses() {
            return ipAddresses;
        }

        /**
         * Sets the list of IP addresses for IP change notifications.
         *
         * @param ipAddresses the list of new IP addresses available for the witness service
         */
        public void setIpAddresses(List<String> ipAddresses) {
            this.ipAddresses = ipAddresses;
        }
    }
}