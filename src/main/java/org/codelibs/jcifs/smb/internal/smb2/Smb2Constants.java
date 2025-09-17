/*
 * © 2017 AgNO3 Gmbh & Co. KG
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
package org.codelibs.jcifs.smb.internal.smb2;

/**
 * Constants for SMB2/SMB3 protocol.
 *
 * This class contains protocol-specific constants, command codes,
 * flags, and other values used in SMB2/SMB3 communication.
 *
 * @author mbechler
 */
public final class Smb2Constants {

    /**
     *
     */
    private Smb2Constants() {
    }

    /**
     * SMB2 header length in bytes
     */
    public static final int SMB2_HEADER_LENGTH = 64;

    /**
     * SMB2 negotiate flag indicating signing is enabled
     */
    public static final int SMB2_NEGOTIATE_SIGNING_ENABLED = 0x0001;

    /**
     * SMB2 negotiate flag indicating signing is required
     */
    public static final int SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002;

    /**
     * SMB 2.0.2 dialect (Windows Vista/Server 2008)
     */
    public static final int SMB2_DIALECT_0202 = 0x0202;

    /**
     * SMB 2.1 dialect (Windows 7/Server 2008R2)
     */
    public static final int SMB2_DIALECT_0210 = 0x0210;

    /**
     * SMB 3.0 dialect (Windows 8/Server 2012)
     */
    public static final int SMB2_DIALECT_0300 = 0x0300;

    /**
     * SMB 3.0.2 dialect (Windows 8.1/Server 2012R2)
     */
    public static final int SMB2_DIALECT_0302 = 0x0302;

    /**
     * SMB 3.1.1 dialect (Windows 10/Server 2016)
     */
    public static final int SMB2_DIALECT_0311 = 0x0311;

    /**
     * SMB2 wildcard dialect for negotiation
     */
    public static final int SMB2_DIALECT_ANY = 0x02FF;

    /**
     * Server supports DFS
     */
    public static final int SMB2_GLOBAL_CAP_DFS = 0x1;

    /**
     * Server supports leasing
     */
    public static final int SMB2_GLOBAL_CAP_LEASING = 0x2;

    /**
     * Server supports multi-credit operations
     */
    public static final int SMB2_GLOBAL_CAP_LARGE_MTU = 0x4;

    /**
     * Server supports multi-channel connections
     */
    public static final int SMB2_GLOBAL_CAP_MULTI_CHANNEL = 0x8;

    /**
     * Server supports persistent handles
     */
    public static final int SMB2_GLOBAL_CAP_PERSISTENT_HANDLES = 0x10;

    /**
     * Server supports directory leasing
     */
    public static final int SMB2_GLOBAL_CAP_DIRECTORY_LEASING = 0x20;

    /**
     * Server supports SMB3 encryption
     */
    public static final int SMB2_GLOBAL_CAP_ENCRYPTION = 0x40;

    /**
     * File information class
     */
    public static final byte SMB2_0_INFO_FILE = 1;

    /**
     * Filesystem information class
     */
    public static final byte SMB2_0_INFO_FILESYSTEM = 2;

    /**
     * Security information class
     */
    public static final byte SMB2_0_INFO_SECURITY = 3;

    /**
     * Quota information class
     */
    public static final byte SMB2_0_INFO_QUOTA = 4;

    /**
     * Unspecified file ID value (all 0xFF bytes)
     */
    public static final byte[] UNSPECIFIED_FILEID =
            { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };

    /**
     * Unspecified tree ID value
     */
    public static final int UNSPECIFIED_TREEID = 0xFFFFFFFF;

    /**
     * Unspecified session ID value
     */
    public static final long UNSPECIFIED_SESSIONID = 0xFFFFFFFFFFFFFFFFL;
}
