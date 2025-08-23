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

/**
 * Enumeration of SMB Witness Event Types as defined in MS-SWN specification.
 * These events represent different types of cluster state changes that clients
 * can be notified about.
 */
public enum WitnessEventType {
    /**
     * Resource state changed - general resource state modification
     */
    RESOURCE_CHANGE(1),

    /**
     * Client should move to different node - directed failover
     */
    CLIENT_MOVE(2),

    /**
     * Share moved to different node - share mobility event
     */
    SHARE_MOVE(3),

    /**
     * IP address changed - network configuration change
     */
    IP_CHANGE(4),

    /**
     * Share deleted - share removal notification
     */
    SHARE_DELETE(5),

    /**
     * Cluster node unavailable - node down event
     */
    NODE_UNAVAILABLE(6),

    /**
     * Cluster node available - node up event
     */
    NODE_AVAILABLE(7);

    private final int value;

    /**
     * Creates a new WitnessEventType with the specified value.
     *
     * @param value the numeric event type value
     */
    WitnessEventType(int value) {
        this.value = value;
    }

    /**
     * Gets the numeric event type value.
     *
     * @return the event type value
     */
    public int getValue() {
        return value;
    }
}
