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
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Credentials;
import org.codelibs.jcifs.smb.NtlmPasswordAuthenticator;
import org.codelibs.jcifs.smb.NtlmPasswordAuthenticator.AuthenticationType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract base implementation of CIFSContext providing common functionality.
 * This class serves as a foundation for concrete CIFS context implementations.
 *
 * @author mbechler
 */
public abstract class AbstractCIFSContext extends Thread implements CIFSContext {

    private static final Logger log = LoggerFactory.getLogger(AbstractCIFSContext.class);
    private boolean closed;

    /**
     * Default constructor that registers a shutdown hook for cleanup
     */
    public AbstractCIFSContext() {
        Runtime.getRuntime().addShutdownHook(this);
    }

    /**
     * @param creds the credentials to use
     * @return a wrapped context with the given credentials
     */
    @Override
    public CIFSContext withCredentials(final Credentials creds) {
        return new CIFSContextCredentialWrapper(this, creds);
    }

    /**
     *
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.CIFSContext#withAnonymousCredentials()
     */
    @Override
    public CIFSContext withAnonymousCredentials() {
        return withCredentials(new NtlmPasswordAuthenticator());
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.CIFSContext#withDefaultCredentials()
     */
    @Override
    public CIFSContext withDefaultCredentials() {
        return withCredentials(getDefaultCredentials());
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.CIFSContext#withGuestCrendentials()
     */
    @Override
    public CIFSContext withGuestCrendentials() {
        return withCredentials(new NtlmPasswordAuthenticator(null, null, (String) null, AuthenticationType.GUEST));
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.CIFSContext#getCredentials()
     */
    @Override
    public Credentials getCredentials() {
        return getDefaultCredentials();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.CIFSContext#hasDefaultCredentials()
     */
    @Override
    public boolean hasDefaultCredentials() {
        return this.getDefaultCredentials() != null && !this.getDefaultCredentials().isAnonymous();
    }

    /**
     * Gets the default credentials for this context.
     *
     * @return the default credentials for this context
     */
    protected abstract Credentials getDefaultCredentials();

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.CIFSContext#renewCredentials(java.lang.String, java.lang.Throwable)
     */
    @Override
    public boolean renewCredentials(final String locationHint, final Throwable error) {
        return false;
    }

    /**
     * {@inheritDoc}
     *
     *
     * @see org.codelibs.jcifs.smb.CIFSContext#close()
     */
    @Override
    public boolean close() throws CIFSException {
        if (!this.closed) {
            Runtime.getRuntime().removeShutdownHook(this);
        }
        return false;
    }

    /**
     * {@inheritDoc}
     *
     * @see java.lang.Thread#run()
     */
    @Override
    public void run() {
        try {
            this.closed = true;
            close();
        } catch (final CIFSException e) {
            log.warn("Failed to close context on shutdown", e);
        }
    }
}
