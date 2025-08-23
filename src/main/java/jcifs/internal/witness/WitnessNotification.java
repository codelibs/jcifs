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

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents a witness notification received from the witness service.
 * Contains event information, resource details, and IP address changes.
 */
public class WitnessNotification {
    private WitnessEventType eventType;
    private long timestamp;
    private String resourceName;
    private final List<WitnessIPAddress> newIPAddresses;
    private final List<WitnessIPAddress> oldIPAddresses;
    private String clientAccessPoint;
    private int flags;
    private String newNodeAddress;

    // Notification flags
    public static final int WITNESS_RESOURCE_STATE_UNKNOWN = 0x00000000;
    public static final int WITNESS_RESOURCE_STATE_AVAILABLE = 0x00000001;
    public static final int WITNESS_RESOURCE_STATE_UNAVAILABLE = 0x000000FF;

    /**
     * Creates a new empty witness notification.
     */
    public WitnessNotification() {
        this.timestamp = System.currentTimeMillis();
        this.newIPAddresses = new ArrayList<>();
        this.oldIPAddresses = new ArrayList<>();
        this.flags = WITNESS_RESOURCE_STATE_UNKNOWN;
    }

    /**
     * Creates a new witness notification.
     *
     * @param eventType the type of event
     * @param resourceName the name of the affected resource
     */
    public WitnessNotification(WitnessEventType eventType, String resourceName) {
        this.eventType = eventType;
        this.resourceName = resourceName;
        this.timestamp = System.currentTimeMillis();
        this.newIPAddresses = new ArrayList<>();
        this.oldIPAddresses = new ArrayList<>();
        this.clientAccessPoint = null;
        this.flags = WITNESS_RESOURCE_STATE_UNKNOWN;
    }

    /**
     * Represents an IP address in a witness notification with associated flags.
     */
    public static class WitnessIPAddress {
        private final InetAddress address;
        private final int flags;

        public static final int IPV4 = 0x01;
        public static final int IPV6 = 0x02;

        /**
         * Creates a new witness IP address.
         *
         * @param address the IP address
         */
        public WitnessIPAddress(InetAddress address) {
            this.address = address;
            this.flags = address.getAddress().length == 4 ? IPV4 : IPV6;
        }

        /**
         * Gets the IP address.
         *
         * @return the IP address
         */
        public InetAddress getAddress() {
            return address;
        }

        /**
         * Gets the address flags.
         *
         * @return the flags
         */
        public int getFlags() {
            return flags;
        }

        /**
         * Checks if this is an IPv4 address.
         *
         * @return true if IPv4
         */
        public boolean isIPv4() {
            return (flags & IPV4) != 0;
        }

        /**
         * Checks if this is an IPv6 address.
         *
         * @return true if IPv6
         */
        public boolean isIPv6() {
            return (flags & IPV6) != 0;
        }
    }

    /**
     * Adds a new IP address to the notification.
     *
     * @param address the new IP address
     */
    public void addNewIPAddress(InetAddress address) {
        newIPAddresses.add(new WitnessIPAddress(address));
    }

    /**
     * Adds an old IP address to the notification.
     *
     * @param address the old IP address
     */
    public void addOldIPAddress(InetAddress address) {
        oldIPAddresses.add(new WitnessIPAddress(address));
    }

    // Getters and Setters

    /**
     * Gets the event type.
     *
     * @return the event type
     */
    public WitnessEventType getEventType() {
        return eventType;
    }

    /**
     * Sets the event type.
     *
     * @param eventType the event type
     */
    public void setEventType(WitnessEventType eventType) {
        this.eventType = eventType;
    }

    /**
     * Gets the resource name.
     *
     * @return the resource name
     */
    public String getResourceName() {
        return resourceName;
    }

    /**
     * Sets the resource name.
     *
     * @param resourceName the resource name
     */
    public void setResourceName(String resourceName) {
        this.resourceName = resourceName;
    }

    /**
     * Gets the notification timestamp.
     *
     * @return the timestamp
     */
    public long getTimestamp() {
        return timestamp;
    }

    /**
     * Sets the timestamp.
     *
     * @param timestamp the timestamp
     */
    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    /**
     * Gets the list of new IP addresses.
     *
     * @return the new IP addresses
     */
    public List<WitnessIPAddress> getNewIPAddresses() {
        return newIPAddresses;
    }

    /**
     * Gets the list of old IP addresses.
     *
     * @return the old IP addresses
     */
    public List<WitnessIPAddress> getOldIPAddresses() {
        return oldIPAddresses;
    }

    /**
     * Gets the notification flags.
     *
     * @return the flags
     */
    public int getFlags() {
        return flags;
    }

    /**
     * Gets the new node address.
     *
     * @return the new node address
     */
    public String getNewNodeAddress() {
        return newNodeAddress;
    }

    /**
     * Sets the new node address.
     *
     * @param newNodeAddress the new node address
     */
    public void setNewNodeAddress(String newNodeAddress) {
        this.newNodeAddress = newNodeAddress;
    }
}
