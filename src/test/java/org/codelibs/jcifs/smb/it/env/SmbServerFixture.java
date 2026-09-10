/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.codelibs.jcifs.smb.it.env;

import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.context.BaseContext;
import org.codelibs.jcifs.smb.impl.NtlmPasswordAuthenticator;

/**
 * Everything a test needs to reach the SMB server the harness resolved.
 *
 * <p>
 * Tests refer to shares by role - the plain share, the encrypted share, the DFS
 * root - never by a literal name, because the two backends are configured with
 * the same vocabulary but the names are settable per environment.
 * </p>
 */
public final class SmbServerFixture {

    /** The default SMB port; a URL only carries the port when it differs from this. */
    private static final int DEFAULT_SMB_PORT = 445;

    private final SmbBackend backend;
    private final String host;
    private final int port;
    private final String domain;
    private final String user;
    private final String password;
    private final String share;
    private final String encryptedShare;
    private final String dfsRoot;

    SmbServerFixture(final SmbBackend backend, final String host, final int port, final String domain, final String user,
            final String password, final String share, final String encryptedShare, final String dfsRoot) {
        this.backend = backend;
        this.host = host;
        this.port = port;
        this.domain = domain;
        this.user = user;
        this.password = password;
        this.share = share;
        this.encryptedShare = encryptedShare;
        this.dfsRoot = dfsRoot;
    }

    /**
     * @return the backend under test
     */
    public SmbBackend backend() {
        return this.backend;
    }

    /**
     * @return the host the server is reachable at
     */
    public String host() {
        return this.host;
    }

    /**
     * @return the port the server is reachable at
     */
    public int port() {
        return this.port;
    }

    /**
     * @return the primary test account
     */
    public String user() {
        return this.user;
    }

    /**
     * @return the password of the primary test account
     */
    public String password() {
        return this.password;
    }

    /**
     * @return the domain of the test accounts, may be null
     */
    public String domain() {
        return this.domain;
    }

    /**
     * @return the name of the plain, unencrypted share
     */
    public String share() {
        return this.share;
    }

    /**
     * @return the name of the share that mandates SMB3 encryption
     */
    public String encryptedShare() {
        return this.encryptedShare;
    }

    /**
     * @return the name of the DFS namespace root
     */
    public String dfsRoot() {
        return this.dfsRoot;
    }

    /**
     * Whether DFS referrals can be followed against this server.
     *
     * <p>
     * A referral names a host but never a port, so the client can only reconnect
     * by following one when the server answers on the default SMB port. A Samba
     * container published on a mapped port therefore cannot serve DFS.
     * </p>
     *
     * @return true when the DFS tests can run
     */
    public boolean dfsAvailable() {
        return this.port == DEFAULT_SMB_PORT;
    }

    /**
     * Builds an SMB URL for a path inside a share.
     *
     * @param shareName the share to address
     * @param path      the path inside the share, may be empty
     * @return the SMB URL
     */
    public String url(final String shareName, final String path) {
        final StringBuilder sb = new StringBuilder("smb://").append(this.host);
        if (this.port != DEFAULT_SMB_PORT) {
            sb.append(':').append(this.port);
        }
        sb.append('/').append(shareName).append('/');
        if (path != null && !path.isEmpty()) {
            sb.append(path);
        }
        return sb.toString();
    }

    /**
     * Builds an SMB URL for the root of a share.
     *
     * @param shareName the share to address
     * @return the SMB URL
     */
    public String url(final String shareName) {
        return url(shareName, "");
    }

    /**
     * @return a context for the primary test account with default settings
     * @throws CIFSException if the configuration is rejected
     */
    public CIFSContext context() throws CIFSException {
        return context(new Properties());
    }

    /**
     * @param overrides configuration properties layered on top of the defaults
     * @return a context for the primary test account
     * @throws CIFSException if the configuration is rejected
     */
    public CIFSContext context(final Properties overrides) throws CIFSException {
        return context(this.user, this.password, overrides);
    }

    /**
     * @param userName the account to authenticate as
     * @param userPassword the password of that account
     * @return a context for the given account
     * @throws CIFSException if the configuration is rejected
     */
    public CIFSContext context(final String userName, final String userPassword) throws CIFSException {
        return context(userName, userPassword, new Properties());
    }

    /**
     * @param userName     the account to authenticate as
     * @param userPassword the password of that account
     * @param overrides    configuration properties layered on top of the defaults
     * @return a context for the given account
     * @throws CIFSException if the configuration is rejected
     */
    public CIFSContext context(final String userName, final String userPassword, final Properties overrides) throws CIFSException {
        final Properties props = defaultProperties();
        props.putAll(overrides);
        final BaseContext context = new BaseContext(new PropertyConfiguration(props));
        if (userName == null) {
            return context;
        }
        return context.withCredentials(new NtlmPasswordAuthenticator(this.domain, userName, userPassword));
    }

    /**
     * The baseline client configuration for every integration test.
     *
     * <p>
     * Note the {@code jcifs.client.} prefix: the {@code jcifs.smb.client.} names
     * were renamed in 3.0.0 and are read back as their defaults, so a test using
     * the old names pins nothing at all.
     * </p>
     *
     * @return a mutable copy of the default properties
     */
    public Properties defaultProperties() {
        final Properties props = new Properties();
        props.setProperty("jcifs.client.minVersion", "SMB202");
        props.setProperty("jcifs.client.maxVersion", "SMB311");
        return props;
    }

    @Override
    public String toString() {
        return "SmbServerFixture[" + this.backend + " " + this.host + ":" + this.port + " user=" + this.user + " share=" + this.share
                + " encrypted=" + this.encryptedShare + " dfs=" + this.dfsRoot + "]";
    }
}
