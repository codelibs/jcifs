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
package jcifs.smb;

import org.bouncycastle.util.encoders.Hex;

/**
 * Authenticator directly specifing the user's NT hash
 *
 * @author mbechler
 *
 */
public class NtlmNtHashAuthenticator extends NtlmPasswordAuthenticator {

    private static final long serialVersionUID = 4328214169536360351L;
    /** The NT hash for authentication */
    private final byte[] ntHash;

    /**
     * Create username/password credentials with specified domain
     *
     * @param domain the authentication domain
     * @param username the username
     * @param passwordHash
     *            NT password hash
     */
    public NtlmNtHashAuthenticator(final String domain, final String username, final byte[] passwordHash) {
        super(domain, username, (String) null, AuthenticationType.USER);
        if (passwordHash == null || passwordHash.length != 16) {
            throw new IllegalArgumentException("Password hash must be provided, expected length 16 byte");
        }
        this.ntHash = passwordHash;
    }

    /**
     * Create username/password credentials with specified domain
     *
     * @param domain the authentication domain
     * @param username the username
     * @param passwordHashHex
     *            NT password hash, hex encoded
     */
    public NtlmNtHashAuthenticator(final String domain, final String username, final String passwordHashHex) {
        this(domain, username, Hex.decode(passwordHashHex));
    }

    private NtlmNtHashAuthenticator(final byte[] passwordHash) {
        this.ntHash = passwordHash;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.smb.NtlmPasswordAuthenticator#getNTHash()
     */
    @Override
    protected byte[] getNTHash() {
        return this.ntHash;
    }

    @Override
    public NtlmPasswordAuthenticator clone() {
        final NtlmNtHashAuthenticator cloned = new NtlmNtHashAuthenticator(this.ntHash.clone());
        cloneInternal(cloned, this);
        return cloned;
    }
}
