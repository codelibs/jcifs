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

import java.util.Locale;
import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.DialectVersion;
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

    /** The lowest dialect the suite ever negotiates when nothing is pinned. */
    private static final DialectVersion DEFAULT_FLOOR = DialectVersion.SMB202;

    /** The highest dialect the suite ever negotiates when nothing is pinned. */
    private static final DialectVersion DEFAULT_CEILING = DialectVersion.SMB311;

    private final SmbBackend backend;
    private final String host;
    private final int port;
    private final String domain;
    private final String user;
    private final String password;
    private final String share;
    private final String encryptedShare;
    private final String dfsRoot;
    private final String symlinkShare;

    SmbServerFixture(final SmbBackend backend, final String host, final int port, final String domain, final String user,
            final String password, final String share, final String encryptedShare, final String dfsRoot, final String symlinkShare) {
        this.backend = backend;
        this.host = host;
        this.port = port;
        this.domain = domain;
        this.user = user;
        this.password = password;
        this.share = share;
        this.encryptedShare = encryptedShare;
        this.dfsRoot = dfsRoot;
        this.symlinkShare = symlinkShare;
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
     * The share whose symbolic links are reported to the client rather than resolved
     * on the server.
     *
     * <p>
     * The plain share resolves a link inside it, which is what most servers do and
     * what the tests there rely on. This one is configured the other way, so that
     * the client sees STATUS_STOPPED_ON_SYMLINK and the target the server named.
     * Samba only behaves this way from 4.22 onwards.
     * </p>
     *
     * @return the name of the share that reports symbolic links
     */
    public String symlinkShare() {
        return this.symlinkShare;
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
        final DialectVersion pinned = pinnedDialect();
        if (pinned == null) {
            props.setProperty("jcifs.client.minVersion", DEFAULT_FLOOR.name());
            props.setProperty("jcifs.client.maxVersion", DEFAULT_CEILING.name());
        } else {
            props.setProperty("jcifs.client.minVersion", pinned.name());
            props.setProperty("jcifs.client.maxVersion", pinned.name());
        }
        return props;
    }

    /**
     * The single dialect this run is pinned to, if any.
     *
     * <p>
     * {@code JCIFS_IT_DIALECT=SMB300} (or {@code -Djcifs.it.dialect=SMB300})
     * pins both ends of the negotiation range so that the whole suite runs on
     * one dialect. CI uses it as a matrix axis: the same tests are proved
     * against SMB 2.0.2, 2.1, 3.0 and 3.1.1 rather than only against whatever
     * the two ends happen to agree on.
     * </p>
     *
     * @return the pinned dialect, or null when the run negotiates freely
     */
    public DialectVersion pinnedDialect() {
        final String configured = SmbServerResolver.setting("DIALECT", null);
        if (configured == null || configured.isBlank()) {
            return null;
        }
        final DialectVersion dialect;
        try {
            dialect = DialectVersion.valueOf(configured.trim().toUpperCase(Locale.ROOT));
        } catch (final IllegalArgumentException e) {
            throw new IllegalStateException("JCIFS_IT_DIALECT must name a DialectVersion, was: " + configured, e);
        }
        if (!dialect.isSMB2()) {
            throw new IllegalStateException("JCIFS_IT_DIALECT must name an SMB2 or SMB3 dialect, was: " + configured
                    + ". The integration tests do not run over SMB1; the unit tests cover it instead.");
        }
        return dialect;
    }

    /**
     * The highest dialect this run is able to negotiate.
     *
     * @return the pinned dialect when one is set, otherwise the suite ceiling
     */
    public DialectVersion dialectCeiling() {
        final DialectVersion pinned = pinnedDialect();
        return pinned == null ? DEFAULT_CEILING : pinned;
    }

    @Override
    public String toString() {
        return "SmbServerFixture[" + this.backend + " " + this.host + ":" + this.port + " user=" + this.user + " share=" + this.share
                + " encrypted=" + this.encryptedShare + " dfs=" + this.dfsRoot + " symlinks=" + this.symlinkShare + "]";
    }
}
