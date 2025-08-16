/* jcifs smb client library in Java
 * Copyright (C) 2004  "Michael B. Allen" <jcifs at samba dot org>
 *                   "Eric Glass" <jcifs at samba dot org>
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

package jcifs.spnego;

import java.io.IOException;

/**
 * Abstract base class for SPNEGO authentication tokens used in GSS-API negotiation
 */
public abstract class SpnegoToken {

    /**
     * Protected constructor for SPNEGO token implementations.
     */
    protected SpnegoToken() {
    }

    private byte[] mechanismToken;

    private byte[] mechanismListMIC;

    /**
     * Gets the inner mechanism token wrapped in this SPNEGO token
     * @return the mechanism token bytes
     */
    public byte[] getMechanismToken() {
        return this.mechanismToken;
    }

    /**
     * Sets the inner mechanism token to be wrapped in this SPNEGO token
     * @param mechanismToken the mechanism token bytes
     */
    public void setMechanismToken(final byte[] mechanismToken) {
        this.mechanismToken = mechanismToken;
    }

    /**
     * Gets the mechanism list MIC (Message Integrity Code) for integrity protection
     * @return the mechanism list MIC bytes
     */
    public byte[] getMechanismListMIC() {
        return this.mechanismListMIC;
    }

    /**
     * Sets the mechanism list MIC (Message Integrity Code) for integrity protection
     * @param mechanismListMIC the mechanism list MIC bytes
     */
    public void setMechanismListMIC(final byte[] mechanismListMIC) {
        this.mechanismListMIC = mechanismListMIC;
    }

    /**
     * Encodes this SPNEGO token to a byte array
     * @return the encoded token bytes
     */
    public abstract byte[] toByteArray();

    /**
     * Parses the provided token bytes to populate this SPNEGO token
     * @param token the token bytes to parse
     * @throws IOException if parsing fails
     */
    protected abstract void parse(byte[] token) throws IOException;

}
