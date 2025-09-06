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
import org.codelibs.jcifs.smb.BufferCacheImpl;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.Credentials;
import org.codelibs.jcifs.smb.CredentialsInternal;
import org.codelibs.jcifs.smb.DfsImpl;
import org.codelibs.jcifs.smb.DfsResolver;
import org.codelibs.jcifs.smb.Handler;
import org.codelibs.jcifs.smb.NameServiceClient;
import org.codelibs.jcifs.smb.NtlmPasswordAuthenticator;
import org.codelibs.jcifs.smb.SIDCacheImpl;
import org.codelibs.jcifs.smb.SidResolver;
import org.codelibs.jcifs.smb.SmbFile;
import org.codelibs.jcifs.smb.SmbNamedPipe;
import org.codelibs.jcifs.smb.SmbPipeResource;
import org.codelibs.jcifs.smb.SmbResource;
import org.codelibs.jcifs.smb.SmbTransportPool;
import org.codelibs.jcifs.smb.SmbTransportPoolImpl;
import org.codelibs.jcifs.smb.netbios.NameServiceClientImpl;

/**
 * Base implementation of CIFS context providing core functionality for SMB operations.
 * This class serves as the foundation for context implementations in the jCIFS library.
 *
 * @author mbechler
 */
public class BaseContext extends AbstractCIFSContext {

    private final Configuration config;
    private final DfsResolver dfs;
    private final SidResolver sidResolver;
    private final Handler urlHandler;
    private final NameServiceClient nameServiceClient;
    private final BufferCache bufferCache;
    private final SmbTransportPool transportPool;
    private final CredentialsInternal defaultCredentials;

    /**
     * Construct a context
     *
     * @param config
     *            configuration for the context
     *
     */
    public BaseContext(final Configuration config) {
        this.config = config;
        this.dfs = new DfsImpl(this);
        this.sidResolver = new SIDCacheImpl(this);
        this.urlHandler = new Handler(this);
        this.nameServiceClient = new NameServiceClientImpl(this);
        this.bufferCache = new BufferCacheImpl(this.config);
        this.transportPool = new SmbTransportPoolImpl();
        final String defUser = config.getDefaultUsername();
        final String defPassword = config.getDefaultPassword();
        final String defDomain = config.getDefaultDomain();
        if (defUser != null) {
            this.defaultCredentials = new NtlmPasswordAuthenticator(defDomain, defUser, defPassword);
        } else {
            this.defaultCredentials = new NtlmPasswordAuthenticator();
        }
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

    @Override
    public SmbTransportPool getTransportPool() {
        return this.transportPool;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.CIFSContext#getConfig()
     */
    @Override
    public Configuration getConfig() {
        return this.config;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.CIFSContext#getDfs()
     */
    @Override
    public DfsResolver getDfs() {
        return this.dfs;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.CIFSContext#getNameServiceClient()
     */
    @Override
    public NameServiceClient getNameServiceClient() {
        return this.nameServiceClient;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.CIFSContext#getBufferCache()
     */
    @Override
    public BufferCache getBufferCache() {
        return this.bufferCache;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.CIFSContext#getUrlHandler()
     */
    @Override
    public URLStreamHandler getUrlHandler() {
        return this.urlHandler;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.CIFSContext#getSIDResolver()
     */
    @Override
    public SidResolver getSIDResolver() {
        return this.sidResolver;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.context.AbstractCIFSContext#getDefaultCredentials()
     */
    @Override
    protected Credentials getDefaultCredentials() {
        return this.defaultCredentials;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.CIFSContext#close()
     */
    @Override
    public boolean close() throws CIFSException {
        boolean inUse = super.close();
        inUse |= this.transportPool.close();
        return inUse;
    }

}
