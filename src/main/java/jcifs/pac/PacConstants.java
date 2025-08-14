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

@SuppressWarnings("javadoc")
public interface PacConstants {

    int PAC_VERSION = 0;

    int LOGON_INFO = 1;
    int CREDENTIAL_TYPE = 2;
    int SERVER_CHECKSUM = 6;
    int PRIVSVR_CHECKSUM = 7;

    int CLIENT_NAME_TYPE = 0xA;
    int CONSTRAINT_DELEGATIION_TYPE = 0xB;
    int CLIENT_UPN_TYPE = 0xC;
    int CLIENT_CLAIMS_TYPE = 0xD;
    int DEVICE_INFO_TYPE = 0xE;
    int DEVICE_CLAIMS_TYPE = 0xF;

    int LOGON_EXTRA_SIDS = 0x20;
    int LOGON_RESOURCE_GROUPS = 0x200;

    int MD5_KRB_SALT = 17;
    int MD5_BLOCK_LENGTH = 64;

}
