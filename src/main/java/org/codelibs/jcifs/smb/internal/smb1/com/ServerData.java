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
package org.codelibs.jcifs.smb.internal.smb1.com;

/**
 * Container for SMB server negotiation data.
 * This class holds the server capabilities, configuration, and security
 * parameters received during SMB protocol negotiation.
 *
 * Stores server-specific data obtained during SMB1 protocol negotiation.
 */
public class ServerData {

    /**
     * Default constructor for ServerData.
     * Creates an empty server data container to be populated during SMB negotiation.
     */
    public ServerData() {
        // Default constructor
    }

    /**
     * Server flags from the SMB header.
     */
    public byte sflags;
    /**
     * Server flags2 field from the SMB header.
     */
    public int sflags2;
    /**
     * Maximum number of outstanding multiplex requests.
     */
    public int smaxMpxCount;
    /**
     * Maximum buffer size the server can handle.
     */
    public int maxBufferSize;
    /**
     * Session key for this connection.
     */
    public int sessKey;
    /**
     * Server capabilities bitmap.
     */
    public int scapabilities;
    /**
     * OEM domain name of the server.
     */
    public String oemDomainName;
    /**
     * Security mode flags.
     */
    public int securityMode;
    /**
     * Security settings for the session.
     */
    public int security;
    /**
     * Whether the server requires encrypted passwords.
     */
    public boolean encryptedPasswords;
    /**
     * Whether message signing is enabled.
     */
    public boolean signaturesEnabled;
    /**
     * Whether message signing is required.
     */
    public boolean signaturesRequired;
    /**
     * Maximum number of virtual circuits.
     */
    public int maxNumberVcs;
    /**
     * Maximum raw buffer size for raw read/write operations.
     */
    public int maxRawSize;
    /**
     * Server's system time.
     */
    public long serverTime;
    /**
     * Server's time zone offset in minutes from UTC.
     */
    public int serverTimeZone;
    /**
     * Length of the encryption key.
     */
    public int encryptionKeyLength;
    /**
     * Encryption key for password encryption.
     */
    public byte[] encryptionKey;
    /**
     * Server's globally unique identifier.
     */
    public byte[] guid;
}