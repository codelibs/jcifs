/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

package jcifs.smb;

import jcifs.CIFSContext;
import jcifs.CIFSException;

/**
 * Unified authentication provider interface for SMB authentication
 *
 * This interface provides a consistent authentication mechanism across
 * SMB1, SMB2, and SMB3 protocols, addressing the issue of multiple
 * scattered authentication implementations.
 */
public interface AuthenticationProvider {

    /**
     * Authentication type enumeration
     */
    enum AuthType {
        NTLM, KERBEROS, SPNEGO, GUEST, ANONYMOUS
    }

    /**
     * Gets the authentication type
     *
     * @return the authentication type
     */
    AuthType getAuthType();

    /**
     * Authenticates using the provided context
     *
     * @param context the CIFS context
     * @param challenge the server challenge (may be null for some auth types)
     * @return authentication response data
     * @throws CIFSException if authentication fails
     */
    byte[] authenticate(CIFSContext context, byte[] challenge) throws CIFSException;

    /**
     * Gets the session key after successful authentication
     *
     * @return the session key or null if not available
     */
    byte[] getSessionKey();

    /**
     * Gets the signing key for SMB2/3
     *
     * @return the signing key or null if not available
     */
    byte[] getSigningKey();

    /**
     * Validates authentication credentials
     *
     * @return true if credentials are valid
     */
    boolean validateCredentials();

    /**
     * Clears sensitive authentication data
     */
    void clearSensitiveData();

    /**
     * Gets authentication metadata for auditing
     *
     * @return authentication metadata
     */
    AuthenticationMetadata getMetadata();

    /**
     * Authentication metadata for auditing and logging
     */
    class AuthenticationMetadata {
        private final String username;
        private final String domain;
        private final AuthType authType;
        private final long timestamp;
        private final String clientAddress;
        private final String serverAddress;

        public AuthenticationMetadata(String username, String domain, AuthType authType, String clientAddress, String serverAddress) {
            this.username = username;
            this.domain = domain;
            this.authType = authType;
            this.timestamp = System.currentTimeMillis();
            this.clientAddress = clientAddress;
            this.serverAddress = serverAddress;
        }

        public String getUsername() {
            return username;
        }

        public String getDomain() {
            return domain;
        }

        public AuthType getAuthType() {
            return authType;
        }

        public long getTimestamp() {
            return timestamp;
        }

        public String getClientAddress() {
            return clientAddress;
        }

        public String getServerAddress() {
            return serverAddress;
        }

        @Override
        public String toString() {
            return String.format("AuthMetadata[user=%s\\%s, type=%s, client=%s, server=%s, time=%d]", domain, username, authType,
                    clientAddress, serverAddress, timestamp);
        }
    }
}
