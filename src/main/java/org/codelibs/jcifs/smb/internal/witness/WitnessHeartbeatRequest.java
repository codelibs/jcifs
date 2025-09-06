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

/**
 * Represents a witness heartbeat request as defined in MS-SWN specification.
 * Used to maintain active witness registrations.
 */
public class WitnessHeartbeatRequest {
    /**
     * Creates a new witness heartbeat request.
     */
    public WitnessHeartbeatRequest() {
        // Default constructor
    }

    private String registrationId;
    private long sequenceNumber;
    private byte[] contextHandle;

    /**
     * Gets the registration ID.
     *
     * @return the registration ID
     */
    public String getRegistrationId() {
        return registrationId;
    }

    /**
     * Sets the registration ID.
     *
     * @param registrationId the registration ID
     */
    public void setRegistrationId(String registrationId) {
        this.registrationId = registrationId;
    }

    /**
     * Gets the sequence number.
     *
     * @return the sequence number
     */
    public long getSequenceNumber() {
        return sequenceNumber;
    }

    /**
     * Sets the sequence number.
     *
     * @param sequenceNumber the sequence number
     */
    public void setSequenceNumber(long sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    /**
     * Gets the context handle.
     *
     * @return the context handle
     */
    public byte[] getContextHandle() {
        return contextHandle;
    }

    /**
     * Sets the context handle.
     *
     * @param contextHandle the context handle
     */
    public void setContextHandle(byte[] contextHandle) {
        this.contextHandle = contextHandle;
    }
}
