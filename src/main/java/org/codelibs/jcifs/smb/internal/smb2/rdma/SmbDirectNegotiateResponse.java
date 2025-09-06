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

import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB Direct Negotiate Response message.
 *
 * As per MS-SMBD 2.2.2 - SMB_DIRECT_NEGOTIATE_RESPONSE
 * This message is sent in response to negotiate SMB Direct protocol parameters.
 */
public class SmbDirectNegotiateResponse {

    // Protocol constants
    /** SMB Direct negotiate response message type */
    public static final int NEGOTIATE_RESPONSE = 0x02;
    /** Status indicating successful negotiation */
    public static final int STATUS_SUCCESS = 0x00000000;
    /** Status indicating SMB Direct is not supported */
    public static final int STATUS_NOT_SUPPORTED = 0x00000001;
    /** Status indicating insufficient resources for SMB Direct */
    public static final int STATUS_INSUFFICIENT_RESOURCES = 0x00000002;

    // Message fields
    private int minVersion;
    private int maxVersion;
    private int negotiatedVersion;
    private int reserved = 0;
    private int creditsGranted;
    private int creditsRequested;
    private int status = STATUS_SUCCESS;
    private int maxReadWriteSize;
    private int preferredSendSize;
    private int maxReceiveSize;
    private int maxFragmentedSize;

    /**
     * Create SMB Direct Negotiate Response
     */
    public SmbDirectNegotiateResponse() {
        // Initialize with defaults
        this.minVersion = SmbDirectNegotiateRequest.MIN_VERSION;
        this.maxVersion = SmbDirectNegotiateRequest.MAX_VERSION;
        this.negotiatedVersion = SmbDirectNegotiateRequest.MAX_VERSION;
        this.creditsGranted = 0;
        this.creditsRequested = RdmaCapabilities.DEFAULT_SEND_CREDIT_TARGET;
        this.maxReadWriteSize = RdmaCapabilities.DEFAULT_MAX_READ_WRITE_SIZE;
        this.preferredSendSize = RdmaCapabilities.DEFAULT_MAX_RECEIVE_SIZE;
        this.maxReceiveSize = RdmaCapabilities.DEFAULT_MAX_RECEIVE_SIZE;
        this.maxFragmentedSize = RdmaCapabilities.DEFAULT_MAX_FRAGMENTED_SIZE;
    }

    /**
     * Decode from byte array
     *
     * @param data source data
     * @param offset starting offset
     * @return decoded response
     */
    public static SmbDirectNegotiateResponse decode(byte[] data, int offset) {
        if (data.length - offset < 32) {
            throw new IllegalArgumentException("Invalid SMB Direct Negotiate Response length");
        }

        SmbDirectNegotiateResponse response = new SmbDirectNegotiateResponse();

        int idx = offset;
        response.minVersion = SMBUtil.readInt2(data, idx);
        idx += 2;
        response.maxVersion = SMBUtil.readInt2(data, idx);
        idx += 2;
        response.negotiatedVersion = SMBUtil.readInt2(data, idx);
        idx += 2;
        response.reserved = SMBUtil.readInt2(data, idx);
        idx += 2;
        response.creditsGranted = SMBUtil.readInt2(data, idx);
        idx += 2;
        response.creditsRequested = SMBUtil.readInt2(data, idx);
        idx += 2;
        response.status = SMBUtil.readInt4(data, idx);
        idx += 4;
        response.maxReadWriteSize = SMBUtil.readInt4(data, idx);
        idx += 4;
        response.preferredSendSize = SMBUtil.readInt4(data, idx);
        idx += 4;
        response.maxReceiveSize = SMBUtil.readInt4(data, idx);
        idx += 4;
        response.maxFragmentedSize = SMBUtil.readInt4(data, idx);
        idx += 4;

        return response;
    }

    /**
     * Encode to byte array
     *
     * @return encoded message
     */
    public byte[] encode() {
        byte[] data = new byte[32];

        int idx = 0;
        SMBUtil.writeInt2(minVersion, data, idx);
        idx += 2;
        SMBUtil.writeInt2(maxVersion, data, idx);
        idx += 2;
        SMBUtil.writeInt2(negotiatedVersion, data, idx);
        idx += 2;
        SMBUtil.writeInt2(reserved, data, idx);
        idx += 2;
        SMBUtil.writeInt2(creditsGranted, data, idx);
        idx += 2;
        SMBUtil.writeInt2(creditsRequested, data, idx);
        idx += 2;
        SMBUtil.writeInt4(status, data, idx);
        idx += 4;
        SMBUtil.writeInt4(maxReadWriteSize, data, idx);
        idx += 4;
        SMBUtil.writeInt4(preferredSendSize, data, idx);
        idx += 4;
        SMBUtil.writeInt4(maxReceiveSize, data, idx);
        idx += 4;
        SMBUtil.writeInt4(maxFragmentedSize, data, idx);

        return data;
    }

    /**
     * Check if negotiation was successful
     *
     * @return true if successful
     */
    public boolean isSuccess() {
        return status == STATUS_SUCCESS;
    }

    // Getters and setters

    /**
     * Get the minimum SMB Direct protocol version
     *
     * @return minimum protocol version
     */
    public int getMinVersion() {
        return minVersion;
    }

    /**
     * Set the minimum SMB Direct protocol version
     *
     * @param minVersion minimum protocol version
     */
    public void setMinVersion(int minVersion) {
        this.minVersion = minVersion;
    }

    /**
     * Get the maximum SMB Direct protocol version
     *
     * @return maximum protocol version
     */
    public int getMaxVersion() {
        return maxVersion;
    }

    /**
     * Set the maximum SMB Direct protocol version
     *
     * @param maxVersion maximum protocol version
     */
    public void setMaxVersion(int maxVersion) {
        this.maxVersion = maxVersion;
    }

    /**
     * Get the negotiated SMB Direct protocol version
     *
     * @return negotiated protocol version
     */
    public int getNegotiatedVersion() {
        return negotiatedVersion;
    }

    /**
     * Set the negotiated SMB Direct protocol version
     *
     * @param negotiatedVersion negotiated protocol version
     */
    public void setNegotiatedVersion(int negotiatedVersion) {
        this.negotiatedVersion = negotiatedVersion;
    }

    /**
     * Get the number of send credits granted
     *
     * @return credits granted
     */
    public int getCreditsGranted() {
        return creditsGranted;
    }

    /**
     * Set the number of send credits granted
     *
     * @param creditsGranted credits to grant
     */
    public void setCreditsGranted(int creditsGranted) {
        this.creditsGranted = creditsGranted;
    }

    /**
     * Get the number of send credits requested
     *
     * @return credits requested
     */
    public int getCreditsRequested() {
        return creditsRequested;
    }

    /**
     * Set the number of send credits requested
     *
     * @param creditsRequested credits to request
     */
    public void setCreditsRequested(int creditsRequested) {
        this.creditsRequested = creditsRequested;
    }

    /**
     * Get the negotiation status
     *
     * @return status code
     */
    public int getStatus() {
        return status;
    }

    /**
     * Set the negotiation status
     *
     * @param status status code
     */
    public void setStatus(int status) {
        this.status = status;
    }

    /**
     * Get the maximum size for RDMA read/write operations
     *
     * @return maximum read/write size in bytes
     */
    public int getMaxReadWriteSize() {
        return maxReadWriteSize;
    }

    /**
     * Set the maximum size for RDMA read/write operations
     *
     * @param maxReadWriteSize maximum read/write size in bytes
     */
    public void setMaxReadWriteSize(int maxReadWriteSize) {
        this.maxReadWriteSize = maxReadWriteSize;
    }

    /**
     * Get the preferred size for send operations
     *
     * @return preferred send size in bytes
     */
    public int getPreferredSendSize() {
        return preferredSendSize;
    }

    /**
     * Set the preferred size for send operations
     *
     * @param preferredSendSize preferred send size in bytes
     */
    public void setPreferredSendSize(int preferredSendSize) {
        this.preferredSendSize = preferredSendSize;
    }

    /**
     * Get the maximum size for receive operations
     *
     * @return maximum receive size in bytes
     */
    public int getMaxReceiveSize() {
        return maxReceiveSize;
    }

    /**
     * Set the maximum size for receive operations
     *
     * @param maxReceiveSize maximum receive size in bytes
     */
    public void setMaxReceiveSize(int maxReceiveSize) {
        this.maxReceiveSize = maxReceiveSize;
    }

    /**
     * Get the maximum size for fragmented operations
     *
     * @return maximum fragmented size in bytes
     */
    public int getMaxFragmentedSize() {
        return maxFragmentedSize;
    }

    /**
     * Set the maximum size for fragmented operations
     *
     * @param maxFragmentedSize maximum fragmented size in bytes
     */
    public void setMaxFragmentedSize(int maxFragmentedSize) {
        this.maxFragmentedSize = maxFragmentedSize;
    }
}