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
package org.codelibs.jcifs.smb.internal.smb2.rdma;

/**
 * RDMA negotiation request parameters.
 *
 * Used during RDMA connection establishment to negotiate
 * protocol version and connection parameters.
 */
public class RdmaNegotiateRequest {

    private int minVersion;
    private int maxVersion;
    private int creditsRequested;
    private int preferredSendSize;
    private int maxReceiveSize;
    private int maxFragmentedSize;

    /**
     * Create new RDMA negotiation request
     */
    public RdmaNegotiateRequest() {
        // Initialize with default values
        this.minVersion = 0x0100; // SMB Direct 1.0
        this.maxVersion = 0x0100; // SMB Direct 1.0
        this.creditsRequested = RdmaCapabilities.DEFAULT_SEND_CREDIT_TARGET;
        this.preferredSendSize = RdmaCapabilities.DEFAULT_MAX_RECEIVE_SIZE;
        this.maxReceiveSize = RdmaCapabilities.DEFAULT_MAX_RECEIVE_SIZE;
        this.maxFragmentedSize = RdmaCapabilities.DEFAULT_MAX_FRAGMENTED_SIZE;
    }

    /**
     * Get minimum protocol version
     *
     * @return minimum version
     */
    public int getMinVersion() {
        return minVersion;
    }

    /**
     * Set minimum protocol version
     *
     * @param minVersion minimum version
     */
    public void setMinVersion(int minVersion) {
        this.minVersion = minVersion;
    }

    /**
     * Get maximum protocol version
     *
     * @return maximum version
     */
    public int getMaxVersion() {
        return maxVersion;
    }

    /**
     * Set maximum protocol version
     *
     * @param maxVersion maximum version
     */
    public void setMaxVersion(int maxVersion) {
        this.maxVersion = maxVersion;
    }

    /**
     * Get number of credits requested
     *
     * @return credits requested
     */
    public int getCreditsRequested() {
        return creditsRequested;
    }

    /**
     * Set number of credits requested
     *
     * @param creditsRequested credits to request
     */
    public void setCreditsRequested(int creditsRequested) {
        this.creditsRequested = creditsRequested;
    }

    /**
     * Get preferred send size
     *
     * @return preferred send size in bytes
     */
    public int getPreferredSendSize() {
        return preferredSendSize;
    }

    /**
     * Set preferred send size
     *
     * @param preferredSendSize preferred send size in bytes
     */
    public void setPreferredSendSize(int preferredSendSize) {
        this.preferredSendSize = preferredSendSize;
    }

    /**
     * Get maximum receive size
     *
     * @return maximum receive size in bytes
     */
    public int getMaxReceiveSize() {
        return maxReceiveSize;
    }

    /**
     * Set maximum receive size
     *
     * @param maxReceiveSize maximum receive size in bytes
     */
    public void setMaxReceiveSize(int maxReceiveSize) {
        this.maxReceiveSize = maxReceiveSize;
    }

    /**
     * Get maximum fragmented size
     *
     * @return maximum fragmented size in bytes
     */
    public int getMaxFragmentedSize() {
        return maxFragmentedSize;
    }

    /**
     * Set maximum fragmented size
     *
     * @param maxFragmentedSize maximum fragmented size in bytes
     */
    public void setMaxFragmentedSize(int maxFragmentedSize) {
        this.maxFragmentedSize = maxFragmentedSize;
    }
}
