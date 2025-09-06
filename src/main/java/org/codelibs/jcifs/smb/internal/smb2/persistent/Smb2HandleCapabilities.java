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
 */
package org.codelibs.jcifs.smb.internal.smb2.persistent;

/**
 * Constants for SMB2/3 durable and persistent handle capabilities.
 */
public final class Smb2HandleCapabilities {

    /**
     * Flag indicating persistent handle capability
     */
    public static final int SMB2_DHANDLE_FLAG_PERSISTENT = 0x00000002;

    /**
     * Default timeout for durable handles (2 minutes)
     */
    public static final long DEFAULT_DURABLE_TIMEOUT = 120000;

    /**
     * Maximum timeout for durable handles (5 minutes)
     */
    public static final long MAX_DURABLE_TIMEOUT = 300000;

    /**
     * Persistent handles have infinite timeout
     */
    public static final long PERSISTENT_TIMEOUT = 0;

    /**
     * Private constructor to prevent instantiation
     */
    private Smb2HandleCapabilities() {
        // Utility class
    }
}
