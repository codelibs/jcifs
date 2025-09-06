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
 * Constants for RDMA capabilities and default configuration values.
 * Based on MS-SMBD specification for SMB Direct protocol.
 */
public class RdmaCapabilities {

    /**
     * RDMA transform capabilities flag indicating response is requested
     */
    public static final int SMB_DIRECT_RESPONSE_REQUESTED = 0x00000001;

    /**
     * Default maximum size for RDMA read/write operations (1MB)
     */
    public static final int DEFAULT_RDMA_READ_WRITE_SIZE = 1048576; // 1MB

    /**
     * Default maximum number of receive credits
     */
    public static final int DEFAULT_RECEIVE_CREDIT_MAX = 255;

    /**
     * Default target number of send credits
     */
    public static final int DEFAULT_SEND_CREDIT_TARGET = 32;

    /**
     * Default maximum receive size (8KB)
     */
    public static final int DEFAULT_MAX_RECEIVE_SIZE = 8192;

    /**
     * Default maximum fragmented size (128KB)
     */
    public static final int DEFAULT_MAX_FRAGMENTED_SIZE = 131072; // 128KB

    /**
     * Default maximum read/write size (1MB)
     */
    public static final int DEFAULT_MAX_READ_WRITE_SIZE = 1048576; // 1MB

    /**
     * Private constructor to prevent instantiation
     */
    private RdmaCapabilities() {
        // Utility class
    }
}
