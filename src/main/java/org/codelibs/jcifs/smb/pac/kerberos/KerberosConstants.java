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
package org.codelibs.jcifs.smb.pac.kerberos;

/**
 * Constants used in Kerberos protocol implementation.
 */
public interface KerberosConstants {

    /** Kerberos OID identifier */
    String KERBEROS_OID = "1.2.840.113554.1.2.2";
    /** Kerberos protocol version */
    String KERBEROS_VERSION = "5";

    /** Kerberos AP-REQ message type */
    String KERBEROS_AP_REQ = "14";

    /** Address family: Internet (IPv4) */
    int AF_INTERNET = 2;
    /** Address family: CHANET */
    int AF_CHANET = 5;
    /** Address family: XNS */
    int AF_XNS = 6;
    /** Address family: ISO */
    int AF_ISO = 7;

    /** Authorization data type: Relevant */
    int AUTH_DATA_RELEVANT = 1;
    /** Authorization data type: PAC */
    int AUTH_DATA_PAC = 128;

    /** DES encryption type identifier */
    int DES_ENC_TYPE = 3;
    /** RC4 encryption type identifier */
    int RC4_ENC_TYPE = 23;
    /** RC4 algorithm name */
    String RC4_ALGORITHM = "ARCFOUR";
    /** HMAC algorithm name */
    String HMAC_ALGORITHM = "HmacMD5";
    /** Size of confounder in bytes */
    int CONFOUNDER_SIZE = 8;
    /** Size of checksum in bytes */
    int CHECKSUM_SIZE = 16;

}
