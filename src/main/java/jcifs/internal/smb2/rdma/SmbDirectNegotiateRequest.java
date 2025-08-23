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
package jcifs.internal.smb2.rdma;

import jcifs.internal.util.SMBUtil;

/**
 * SMB Direct Negotiate Request message.
 *
 * As per MS-SMBD 2.2.1 - SMB_DIRECT_NEGOTIATE_REQUEST
 * This message is sent to negotiate SMB Direct protocol parameters.
 */
public class SmbDirectNegotiateRequest {

    // Protocol constants
    public static final int MIN_VERSION = 0x0100; // SMB Direct 1.0
    public static final int MAX_VERSION = 0x0100; // SMB Direct 1.0
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

    public int getMinVersion() {
        return minVersion;
    }

    public void setMinVersion(int minVersion) {
        this.minVersion = minVersion;
    }

    public int getMaxVersion() {
        return maxVersion;
    }

    public void setMaxVersion(int maxVersion) {
        this.maxVersion = maxVersion;
    }

    public int getCreditsRequested() {
        return creditsRequested;
    }

    public void setCreditsRequested(int creditsRequested) {
        this.creditsRequested = creditsRequested;
    }

    public int getPreferredSendSize() {
        return preferredSendSize;
    }

    public void setPreferredSendSize(int preferredSendSize) {
        this.preferredSendSize = preferredSendSize;
    }

    public int getMaxReceiveSize() {
        return maxReceiveSize;
    }

    public void setMaxReceiveSize(int maxReceiveSize) {
        this.maxReceiveSize = maxReceiveSize;
    }

    public int getMaxFragmentedSize() {
        return maxFragmentedSize;
    }

    public void setMaxFragmentedSize(int maxFragmentedSize) {
        this.maxFragmentedSize = maxFragmentedSize;
    }
}