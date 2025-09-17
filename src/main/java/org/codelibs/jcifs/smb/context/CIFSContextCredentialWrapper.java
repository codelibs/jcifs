/*
 * © 2016 AgNO3 Gmbh & Co. KG
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
package org.codelibs.jcifs.smb.context;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Credentials;
import org.codelibs.jcifs.smb.impl.CredentialsInternal;
import org.codelibs.jcifs.smb.impl.NtlmAuthenticator;
import org.codelibs.jcifs.smb.impl.NtlmPasswordAuthenticator;
import org.codelibs.jcifs.smb.impl.SmbAuthException;
import org.codelibs.jcifs.smb.impl.SmbRenewableCredentials;

/**
 * Context wrapper supplying alternate credentials
 *
 * @author mbechler
 *
 */
public final class CIFSContextCredentialWrapper extends CIFSContextWrapper implements CIFSContext {

    private Credentials creds;

    /**
     * Constructs a CIFS context wrapper with custom credentials.
     *
     * @param delegate the context to wrap
     * @param creds
     *            Credentials to use
     */
    public CIFSContextCredentialWrapper(final AbstractCIFSContext delegate, final Credentials creds) {
        super(delegate);
        this.creds = creds;
    }

    /**
     *
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.context.CIFSContextWrapper#getCredentials()
     */
    @Override
    public Credentials getCredentials() {
        return this.creds;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.CIFSContext#renewCredentials(java.lang.String, java.lang.Throwable)
     */
    @Override
    public boolean renewCredentials(final String locationHint, final Throwable error) {
        final Credentials cred = getCredentials();
        if (cred instanceof final SmbRenewableCredentials renewable) {
            final CredentialsInternal renewed = renewable.renew();
            if (renewed != null) {
                this.creds = renewed;
                return true;
            }
        }
        final NtlmAuthenticator auth = NtlmAuthenticator.getDefault();
        if (auth != null) {
            final NtlmPasswordAuthenticator newAuth =
                    NtlmAuthenticator.requestNtlmPasswordAuthentication(auth, locationHint, error instanceof SmbAuthException s ? s : null);
            if (newAuth != null) {
                this.creds = newAuth;
                return true;
            }
        }
        return false;
    }
}
