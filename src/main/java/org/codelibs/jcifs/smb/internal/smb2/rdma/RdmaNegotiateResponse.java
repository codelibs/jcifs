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
 * RDMA negotiation response parameters.
 *
 * Contains the negotiated parameters returned by the RDMA peer
 * during connection establishment.
 */
public class RdmaNegotiateResponse {

    private int status;
    private int selectedVersion;
    private int creditsGranted;
    private int maxReceiveSize;
    private int maxReadWriteSize;
    private int maxFragmentedSize;

    /**
     * Create new RDMA negotiation response
     */
    public RdmaNegotiateResponse() {
        // Initialize with default values
        this.status = 0; // Success
        this.selectedVersion = 0x0100; // SMB Direct 1.0
        this.creditsGranted = 0;
        this.maxReceiveSize = RdmaCapabilities.DEFAULT_MAX_RECEIVE_SIZE;
        this.maxReadWriteSize = RdmaCapabilities.DEFAULT_MAX_READ_WRITE_SIZE;
        this.maxFragmentedSize = RdmaCapabilities.DEFAULT_MAX_FRAGMENTED_SIZE;
    }

    /**
     * Check if negotiation was successful
     *
     * @return true if successful, false otherwise
     */
    public boolean isSuccess() {
        return status == 0;
    }

    /**
     * Get negotiation status
     *
     * @return status code (0 = success)
     */
    public int getStatus() {
        return status;
    }

    /**
     * Set negotiation status
     *
     * @param status status code
     */
    public void setStatus(int status) {
        this.status = status;
    }

    /**
     * Get selected protocol version
     *
     * @return selected version
     */
    public int getSelectedVersion() {
        return selectedVersion;
    }

    /**
     * Set selected protocol version
     *
     * @param selectedVersion selected version
     */
    public void setSelectedVersion(int selectedVersion) {
        this.selectedVersion = selectedVersion;
    }

    /**
     * Get number of credits granted
     *
     * @return credits granted
     */
    public int getCreditsGranted() {
        return creditsGranted;
    }

    /**
     * Set number of credits granted
     *
     * @param creditsGranted credits granted
     */
    public void setCreditsGranted(int creditsGranted) {
        this.creditsGranted = creditsGranted;
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
     * Get maximum read/write size
     *
     * @return maximum read/write size in bytes
     */
    public int getMaxReadWriteSize() {
        return maxReadWriteSize;
    }

    /**
     * Set maximum read/write size
     *
     * @param maxReadWriteSize maximum read/write size in bytes
     */
    public void setMaxReadWriteSize(int maxReadWriteSize) {
        this.maxReadWriteSize = maxReadWriteSize;
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
