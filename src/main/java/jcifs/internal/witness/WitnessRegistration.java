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
import java.util.concurrent.atomic.AtomicLong;

/**
 * Represents a witness service registration for SMB resource monitoring.
 * This class maintains registration state, heartbeat information, and
 * sequence numbers for witness protocol communication.
 */
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

    /**
     * Enumeration of possible witness registration states.
     */
    public enum WitnessRegistrationState {
        REGISTERING, REGISTERED, UNREGISTERING, FAILED, EXPIRED
    }

    /**
     * Creates a new witness registration.
     *
     * @param shareName the SMB share name to monitor
     * @param serverAddress the server IP address
     * @param serviceType the type of witness service
     */
    public WitnessRegistration(String shareName, InetAddress serverAddress, WitnessServiceType serviceType) {
        this.registrationId = generateRegistrationId();
        this.shareName = shareName;
        this.serverAddress = serverAddress;
        this.serviceType = serviceType;
        this.version = WitnessVersion.VERSION_2; // Use latest by default
        this.registrationTime = System.currentTimeMillis();
        this.sequenceNumber = new AtomicLong(0);
        this.state = WitnessRegistrationState.REGISTERING;
        this.lastHeartbeat = registrationTime;
        this.flags = WITNESS_REGISTER_IP_NOTIFICATION;
    }

    /**
     * Generates a unique registration ID.
     *
     * @return a unique registration identifier
     */
    private String generateRegistrationId() {
        return "REG-" + System.currentTimeMillis() + "-" + Integer.toHexString(System.identityHashCode(this));
    }

    /**
     * Gets the next sequence number for this registration.
     *
     * @return the next sequence number
     */
    public long getNextSequenceNumber() {
        return sequenceNumber.incrementAndGet();
    }

    /**
     * Updates the heartbeat timestamp to current time.
     */
    public void updateHeartbeat() {
        this.lastHeartbeat = System.currentTimeMillis();
    }

    /**
     * Checks if this registration has expired based on the timeout.
     *
     * @param timeoutMs the timeout in milliseconds
     * @return true if the registration is expired
     */
    public boolean isExpired(long timeoutMs) {
        return System.currentTimeMillis() - lastHeartbeat > timeoutMs;
    }

    // Getters and setters

    /**
     * Gets the last heartbeat timestamp.
     *
     * @return the last heartbeat timestamp in milliseconds
     */
    public long getLastHeartbeat() {
        return lastHeartbeat;
    }

    /**
     * Gets the registration ID.
     *
     * @return the registration ID
     */
    public String getRegistrationId() {
        return registrationId;
    }

    /**
     * Gets the share name.
     *
     * @return the share name
     */
    public String getShareName() {
        return shareName;
    }

    /**
     * Gets the server address.
     *
     * @return the server address
     */
    public InetAddress getServerAddress() {
        return serverAddress;
    }

    /**
     * Gets the service type.
     *
     * @return the service type
     */
    public WitnessServiceType getServiceType() {
        return serviceType;
    }

    /**
     * Gets the witness version.
     *
     * @return the witness version
     */
    public WitnessVersion getVersion() {
        return version;
    }

    /**
     * Gets the registration state.
     *
     * @return the current registration state
     */
    public WitnessRegistrationState getState() {
        return state;
    }

    /**
     * Sets the registration state.
     *
     * @param state the new registration state
     */
    public void setState(WitnessRegistrationState state) {
        this.state = state;
    }

    /**
     * Gets the registration flags.
     *
     * @return the registration flags
     */
    public int getFlags() {
        return flags;
    }

    /**
     * Sets the registration flags.
     *
     * @param flags the registration flags
     */
    public void setFlags(int flags) {
        this.flags = flags;
    }
}
