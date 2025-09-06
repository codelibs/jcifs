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
 * SMB Direct Negotiate Request message.
 *
 * As per MS-SMBD 2.2.1 - SMB_DIRECT_NEGOTIATE_REQUEST
 * This message is sent to negotiate SMB Direct protocol parameters.
 */
public class SmbDirectNegotiateRequest {

    // Protocol constants
    /** Minimum supported SMB Direct protocol version (1.0) */
    public static final int MIN_VERSION = 0x0100; // SMB Direct 1.0
    /** Maximum supported SMB Direct protocol version (1.0) */
    public static final int MAX_VERSION = 0x0100; // SMB Direct 1.0
    /** SMB Direct negotiate request message type */
    public static final int NEGOTIATE_REQUEST = 0x01;

    // Message fields
    private int minVersion = MIN_VERSION;
    private int maxVersion = MAX_VERSION;
    private int reserved = 0;
    private int creditsRequested = RdmaCapabilities.DEFAULT_SEND_CREDIT_TARGET;
    private int preferredSendSize = RdmaCapabilities.DEFAULT_MAX_RECEIVE_SIZE;
    private int maxReceiveSize = RdmaCapabilities.DEFAULT_MAX_RECEIVE_SIZE;
    private int maxFragmentedSize = RdmaCapabilities.DEFAULT_MAX_FRAGMENTED_SIZE;

    /**
     * Create SMB Direct Negotiate Request
     */
    public SmbDirectNegotiateRequest() {
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
        SMBUtil.writeInt2(reserved, data, idx);
        idx += 2;
        SMBUtil.writeInt2(creditsRequested, data, idx);
        idx += 2;
        SMBUtil.writeInt4(preferredSendSize, data, idx);
        idx += 4;
        SMBUtil.writeInt4(maxReceiveSize, data, idx);
        idx += 4;
        SMBUtil.writeInt4(maxFragmentedSize, data, idx);
        idx += 4;

        // Reserved fields (8 bytes)
        // Already zero-initialized

        return data;
    }

    /**
     * Get size of this message
     *
     * @return size in bytes (32)
     */
    public static int size() {
        return 32;
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