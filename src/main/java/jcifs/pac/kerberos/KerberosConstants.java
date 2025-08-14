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
package jcifs.pac.kerberos;

public interface KerberosConstants {

    String KERBEROS_OID = "1.2.840.113554.1.2.2";
    String KERBEROS_VERSION = "5";

    String KERBEROS_AP_REQ = "14";

    int AF_INTERNET = 2;
    int AF_CHANET = 5;
    int AF_XNS = 6;
    int AF_ISO = 7;

    int AUTH_DATA_RELEVANT = 1;
    int AUTH_DATA_PAC = 128;

    int DES_ENC_TYPE = 3;
    int RC4_ENC_TYPE = 23;
    String RC4_ALGORITHM = "ARCFOUR";
    String HMAC_ALGORITHM = "HmacMD5";
    int CONFOUNDER_SIZE = 8;
    int CHECKSUM_SIZE = 16;

}
