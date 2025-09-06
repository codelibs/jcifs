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
package org.codelibs.jcifs.smb.internal.smb2.multichannel;

/**
 * SMB2/SMB3 Multi-Channel capabilities and constants
 */
public final class Smb2ChannelCapabilities {

    private Smb2ChannelCapabilities() {
    }

    /**
     * Multi-channel specific capability flag
     */
    public static final int SMB2_GLOBAL_CAP_MULTI_CHANNEL = 0x00000008;

    /**
     * Channel binding is disabled
     */
    public static final int CHANNEL_BINDING_DISABLED = 0;

    /**
     * Channel binding is preferred but not required
     */
    public static final int CHANNEL_BINDING_PREFERRED = 1;

    /**
     * Channel binding is required
     */
    public static final int CHANNEL_BINDING_REQUIRED = 2;

    /**
     * Default maximum number of channels per session
     */
    public static final int DEFAULT_MAX_CHANNELS = 4;

    /**
     * Absolute maximum number of channels supported
     */
    public static final int ABSOLUTE_MAX_CHANNELS = 32;

    /**
     * Network interface capability flag for RSS support
     */
    public static final int NETWORK_INTERFACE_CAP_RSS = 0x00000001;

    /**
     * Network interface capability flag for RDMA support
     */
    public static final int NETWORK_INTERFACE_CAP_RDMA = 0x00000002;

    /**
     * FSCTL code for querying network interface information
     */
    public static final int FSCTL_QUERY_NETWORK_INTERFACE_INFO = 0x001401FC;

    /**
     * SMB2 session flag indicating channel binding
     */
    public static final int SMB2_SESSION_FLAG_BINDING = 0x01;

    /**
     * Size of network interface info structure in bytes
     */
    public static final int NETWORK_INTERFACE_INFO_SIZE = 152;
}
