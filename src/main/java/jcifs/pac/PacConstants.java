/*
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
package jcifs.pac;

/**
 * Constants for PAC (Privilege Attribute Certificate) data structures.
 * Defines buffer types and other constants used in PAC parsing and validation.
 */
public interface PacConstants {

    /**
     * PAC structure version number.
     */
    int PAC_VERSION = 0;

    /**
     * Buffer type for user logon information.
     */
    int LOGON_INFO = 1;
    /**
     * Buffer type for credential information.
     */
    int CREDENTIAL_TYPE = 2;
    /**
     * Buffer type for server checksum signature.
     */
    int SERVER_CHECKSUM = 6;
    /**
     * Buffer type for privilege server (KDC) checksum signature.
     */
    int PRIVSVR_CHECKSUM = 7;

    /**
     * Buffer type for client name information.
     */
    int CLIENT_NAME_TYPE = 0xA;
    /**
     * Buffer type for constrained delegation information.
     */
    int CONSTRAINT_DELEGATIION_TYPE = 0xB;
    /**
     * Buffer type for client user principal name.
     */
    int CLIENT_UPN_TYPE = 0xC;
    /**
     * Buffer type for client claims information.
     */
    int CLIENT_CLAIMS_TYPE = 0xD;
    /**
     * Buffer type for device information.
     */
    int DEVICE_INFO_TYPE = 0xE;
    /**
     * Buffer type for device claims information.
     */
    int DEVICE_CLAIMS_TYPE = 0xF;

    /**
     * Flag for extra SIDs in logon information.
     */
    int LOGON_EXTRA_SIDS = 0x20;
    /**
     * Flag for resource groups in logon information.
     */
    int LOGON_RESOURCE_GROUPS = 0x200;

    /**
     * Kerberos salt type for MD5 checksums.
     */
    int MD5_KRB_SALT = 17;
    /**
     * MD5 block length in bytes.
     */
    int MD5_BLOCK_LENGTH = 64;

}
