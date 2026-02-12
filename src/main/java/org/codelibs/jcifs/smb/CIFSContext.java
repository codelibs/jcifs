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
package org.codelibs.jcifs.smb;

import java.net.URLStreamHandler;

/**
 * Encapsulation of client context
 *
 *
 * A context holds the client configuration, shared services as well as the active credentials.
 *
 * Usually you will want to create one context per client configuration and then
 * multiple sub-contexts using different credentials (if necessary).
 *
 * {@link #withDefaultCredentials()}, {@link #withAnonymousCredentials()}, {@link #withCredentials(Credentials)}
 * allow to create such sub-contexts.
 *
 *
 * Implementors of this interface should extend {@link org.codelibs.jcifs.smb.context.BaseContext} or
 * {@link org.codelibs.jcifs.smb.context.CIFSContextWrapper} to get forward compatibility.
 *
 * @author mbechler
 *
 */
public interface CIFSContext {

    /**
     * Get a resource
     *
     * @param url the URL of the SMB resource
     * @return the SMB resource at the specified location
     * @throws CIFSException if the resource cannot be accessed
     */
    SmbResource get(String url) throws CIFSException;

    /**
     * Get a pipe resource
     *
     * @param url the URL of the SMB pipe resource
     * @param pipeType
     *            the type of the pipe
     * @return the SMB pipe resource at the specified location
     * @throws CIFSException if the pipe resource cannot be accessed
     */
    SmbPipeResource getPipe(String url, int pipeType) throws CIFSException;

    /**
     * Close all connections and release resources associated with this context
     *
     * @return whether any connection was still in use
     * @throws CIFSException if an error occurs during cleanup
     */
    boolean close() throws CIFSException;

    /**
     * Get the configuration object for this context
     *
     * @return the active configuration
     */
    Configuration getConfig();

    /**
     * Get the name service client for NetBIOS name resolution
     *
     * @return the name server client
     */
    NameServiceClient getNameServiceClient();

    /**
     * Get the buffer cache for efficient memory management
     *
     * @return the buffer cache
     */
    BufferCache getBufferCache();

    /**
     * Get the transport pool for managing SMB connections
     *
     * @return the transport pool
     */
    SmbTransportPool getTransportPool();

    /**
     * Get the DFS resolver for handling distributed file system paths
     *
     * @return the DFS instance for this context
     */
    DfsResolver getDfs();

    /**
     * Get the SID resolver for resolving security identifiers
     *
     * @return the SID resolver for this context
     */
    SidResolver getSIDResolver();

    /**
     * Get the credentials associated with this context
     *
     * @return the used credentials
     */
    Credentials getCredentials();

    /**
     * Get a URL stream handler for SMB URLs
     *
     * @return an URL handler using this context
     */
    URLStreamHandler getUrlHandler();

    /**
     * Check if default credentials are configured
     *
     * @return whether default credentials are available
     */
    boolean hasDefaultCredentials();

    /**
     * Create a child context with default credentials
     *
     * @return a child context using the configured default credentials
     */
    CIFSContext withDefaultCredentials();

    /**
     * Create a child context with anonymous credentials
     *
     * @return a child context using anonymous credentials
     */
    CIFSContext withAnonymousCredentials();

    /**
     * Create a child context with guest credentials
     *
     * @return a child context using guest credentials
     */
    CIFSContext withGuestCredentials();

    /**
     * Create a child context with specified credentials
     *
     * The credentials must be usable as internal credentials via
     * {@code creds.unwrap(CredentialsInternal.class)}.
     *
     * @param creds the credentials to use
     * @return a child context using using the given credentials
     */
    CIFSContext withCredentials(Credentials creds);

    /**
     * Attempt to renew credentials after authentication failure
     *
     * @param locationHint URL or location hint for credential renewal
     * @param error the error that triggered renewal
     * @return whether new credentials are obtained
     */
    boolean renewCredentials(String locationHint, Throwable error);

}
