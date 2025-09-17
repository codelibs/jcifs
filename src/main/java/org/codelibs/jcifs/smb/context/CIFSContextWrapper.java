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

import java.net.MalformedURLException;
import java.net.URLStreamHandler;

import org.codelibs.jcifs.smb.BufferCache;
import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.Credentials;
import org.codelibs.jcifs.smb.DfsResolver;
import org.codelibs.jcifs.smb.NameServiceClient;
import org.codelibs.jcifs.smb.SidResolver;
import org.codelibs.jcifs.smb.SmbPipeResource;
import org.codelibs.jcifs.smb.SmbResource;
import org.codelibs.jcifs.smb.SmbTransportPool;
import org.codelibs.jcifs.smb.impl.Handler;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.impl.SmbNamedPipe;

/**
 * A wrapper implementation of CIFSContext that delegates to another context.
 * This class allows for context decoration and customization through delegation.
 *
 * @author mbechler
 */
public class CIFSContextWrapper implements CIFSContext {

    private final CIFSContext delegate;
    private Handler wrappedHandler;

    /**
     * Constructs a wrapper around the specified CIFS context.
     *
     * @param delegate
     *            context to delegate non-override methods to
     *
     */
    public CIFSContextWrapper(final CIFSContext delegate) {
        this.delegate = delegate;
    }

    /**
     * {@inheritDoc}
     *
     * @throws CIFSException if the URL is malformed or there is an error creating the SMB resource
     *
     * @see org.codelibs.jcifs.smb.CIFSContext#get(java.lang.String)
     */
    @Override
    public SmbResource get(final String url) throws CIFSException {
        try {
            return new SmbFile(url, this);
        } catch (final MalformedURLException e) {
            throw new CIFSException("Invalid URL " + url, e);
        }
    }

    /**
     *
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.CIFSContext#getPipe(java.lang.String, int)
     */
    @Override
    public SmbPipeResource getPipe(final String url, final int pipeType) throws CIFSException {
        try {
            return new SmbNamedPipe(url, pipeType, this);
        } catch (final MalformedURLException e) {
            throw new CIFSException("Invalid URL " + url, e);
        }
    }

    /**
     * Wraps a new context, allowing subclasses to provide custom wrapping behavior.
     *
     * @param newContext the context to wrap
     * @return the wrapped context
     */
    protected CIFSContext wrap(final CIFSContext newContext) {
        return newContext;
    }

    @Override
    public Configuration getConfig() {
        return this.delegate.getConfig();
    }

    @Override
    public DfsResolver getDfs() {
        return this.delegate.getDfs();
    }

    @Override
    public Credentials getCredentials() {
        return this.delegate.getCredentials();
    }

    @Override
    public URLStreamHandler getUrlHandler() {
        if (this.wrappedHandler == null) {
            this.wrappedHandler = new Handler(this);
        }
        return this.wrappedHandler;
    }

    @Override
    public SidResolver getSIDResolver() {
        return this.delegate.getSIDResolver();
    }

    @Override
    public boolean hasDefaultCredentials() {
        return this.delegate.hasDefaultCredentials();
    }

    @Override
    public CIFSContext withCredentials(final Credentials creds) {
        return wrap(this.delegate.withCredentials(creds));
    }

    @Override
    public CIFSContext withDefaultCredentials() {
        return wrap(this.delegate.withDefaultCredentials());
    }

    @Override
    public CIFSContext withAnonymousCredentials() {
        return wrap(this.delegate.withAnonymousCredentials());
    }

    @Override
    public CIFSContext withGuestCrendentials() {
        return wrap(this.delegate.withGuestCrendentials());
    }

    @Override
    public boolean renewCredentials(final String locationHint, final Throwable error) {
        return this.delegate.renewCredentials(locationHint, error);
    }

    @Override
    public NameServiceClient getNameServiceClient() {
        return this.delegate.getNameServiceClient();
    }

    @Override
    public BufferCache getBufferCache() {
        return this.delegate.getBufferCache();
    }

    @Override
    public SmbTransportPool getTransportPool() {
        return this.delegate.getTransportPool();
    }

    @Override
    public boolean close() throws CIFSException {
        return this.delegate.close();
    }
}
