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

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Locale;

import org.opentest4j.TestAbortedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;

/**
 * Decides which SMB server the integration tests talk to, and starts one if the
 * environment did not supply it.
 *
 * <p>
 * Three shapes are supported by a single rule:
 * </p>
 * <ul>
 * <li>nothing configured - a Samba container is started by the harness</li>
 * <li>{@code JCIFS_IT_BACKEND=windows} plus a host - a real Windows server</li>
 * <li>{@code JCIFS_IT_BACKEND=samba} plus a host - an external Samba</li>
 * </ul>
 *
 * <p>
 * When {@code JCIFS_IT_REQUIRED=true} a missing or unusable environment is a
 * failure rather than a skip. CI sets it, so a job cannot pass by quietly
 * skipping every integration test.
 * </p>
 */
public final class SmbServerResolver {

    private static final Logger log = LoggerFactory.getLogger(SmbServerResolver.class);

    /** Directory holding the Dockerfile and fixtures for the Samba backend. */
    private static final Path SAMBA_CONTEXT = Path.of("build_helpers", "samba");

    /** Kept stable so repeated local runs reuse the built image instead of rebuilding. */
    private static final String SAMBA_IMAGE_NAME = "jcifs-it-samba:test";

    private static final String DEFAULT_USER = "testuser1";
    private static final String SECONDARY_USER = "testuser2";
    /**
     * Password of the accounts the fixture scripts create. It is not a secret:
     * the account only exists on the container or CI runner that the setup
     * script just built, and is thrown away with it.
     */
    private static final String DEFAULT_PASSWORD = "Public-Fixture-Not-A-Secret-1!";
    private static final String DEFAULT_SHARE = "share";
    private static final String DEFAULT_ENCRYPTED_SHARE = "share-encrypted";
    private static final String DEFAULT_DFS_ROOT = "dfs";
    private static final String DEFAULT_SYMLINK_SHARE = "symlinks";

    private static SmbServerFixture fixture;
    private static TestAbortedException skipped;
    private static GenericContainer<?> container;

    private SmbServerResolver() {
    }

    /**
     * @return the account the fixture does not authenticate as by default, used
     *         by the authorization tests
     */
    public static String secondaryUser() {
        return SECONDARY_USER;
    }

    /**
     * @return true when the environment forbids skipping integration tests
     */
    public static boolean required() {
        return Boolean.parseBoolean(setting("REQUIRED", "false"));
    }

    /**
     * Resolves - and on the first call possibly starts - the SMB server.
     *
     * @return the fixture describing how to reach it
     */
    public static synchronized SmbServerFixture resolve() {
        if (fixture != null) {
            return fixture;
        }
        if (skipped != null) {
            throw skipped;
        }
        try {
            fixture = build();
            log.info("SMB integration tests are running against {}", fixture);
            return fixture;
        } catch (final TestAbortedException e) {
            skipped = e;
            throw e;
        }
    }

    private static SmbServerFixture build() {
        final String backendSetting = setting("BACKEND", null);
        final String host = setting("HOST", null);

        if (backendSetting != null || host != null) {
            return externalServer(backendSetting, host);
        }
        return containerServer();
    }

    private static SmbServerFixture externalServer(final String backendSetting, final String host) {
        final SmbBackend backend = parseBackend(backendSetting);
        if (host == null) {
            throw unusable("JCIFS_IT_BACKEND is set to " + backend + " but JCIFS_IT_HOST is not set");
        }
        return new SmbServerFixture(backend, host, Integer.parseInt(setting("PORT", "445")), setting("DOMAIN", null),
                setting("USER", DEFAULT_USER), setting("PASSWORD", DEFAULT_PASSWORD), setting("SHARE", DEFAULT_SHARE),
                setting("SHARE_ENCRYPTED", DEFAULT_ENCRYPTED_SHARE), setting("DFS_ROOT", DEFAULT_DFS_ROOT),
                setting("SHARE_SYMLINKS", DEFAULT_SYMLINK_SHARE));
    }

    private static SmbBackend parseBackend(final String value) {
        if (value == null) {
            return SmbBackend.SAMBA;
        }
        try {
            return SmbBackend.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (final IllegalArgumentException e) {
            throw new IllegalStateException("JCIFS_IT_BACKEND must be 'samba' or 'windows', was: " + value, e);
        }
    }

    private static SmbServerFixture containerServer() {
        if (!Files.isDirectory(SAMBA_CONTEXT)) {
            throw new IllegalStateException("Samba build context not found at " + SAMBA_CONTEXT.toAbsolutePath()
                    + ". Integration tests must be run from the project root.");
        }
        if (!DockerClientFactory.instance().isDockerAvailable()) {
            throw unusable("no Docker daemon is available to start the Samba backend");
        }

        // Try the default port first. DFS referrals name a host but never a port,
        // so a client can only follow them when the server answers on 445. CI
        // hosts have 445 free; a developer machine sharing files usually does not,
        // and then the DFS tests skip instead of failing.
        container = startSamba(true);
        if (container == null) {
            log.info("Port 445 is not available on this host; the Samba backend will use a mapped port and DFS tests will skip");
            container = startSamba(false);
        }

        return new SmbServerFixture(SmbBackend.SAMBA, container.getHost(), container.getMappedPort(445), null, DEFAULT_USER,
                DEFAULT_PASSWORD, DEFAULT_SHARE, DEFAULT_ENCRYPTED_SHARE, DEFAULT_DFS_ROOT, DEFAULT_SYMLINK_SHARE);
    }

    private static GenericContainer<?> startSamba(final boolean bindDefaultPort) {
        final GenericContainer<?> candidate =
                new GenericContainer<>(new ImageFromDockerfile(SAMBA_IMAGE_NAME, false).withFileFromPath(".", SAMBA_CONTEXT))
                        .withExposedPorts(445)
                        .waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofMinutes(3)))
                        .withLogConsumer(new Slf4jLogConsumer(log).withPrefix("samba"));
        if (bindDefaultPort) {
            candidate.setPortBindings(List.of("445:445"));
        }
        try {
            candidate.start();
            return candidate;
        } catch (final RuntimeException e) {
            if (!bindDefaultPort) {
                throw e;
            }
            log.debug("Could not publish the Samba container on port 445", e);
            try {
                candidate.stop();
            } catch (final RuntimeException stopFailure) {
                log.debug("Ignoring failure while discarding the container", stopFailure);
            }
            return null;
        }
    }

    /**
     * A missing environment skips by default and fails when CI demands the tests
     * actually run.
     */
    private static RuntimeException unusable(final String reason) {
        if (required()) {
            return new IllegalStateException("SMB integration tests are required but " + reason);
        }
        return new TestAbortedException("Skipping SMB integration tests: " + reason);
    }

    /**
     * Reads a setting from {@code JCIFS_IT_<NAME>} or {@code jcifs.it.<name>}.
     */
    static String setting(final String name, final String fallback) {
        final String fromEnv = System.getenv("JCIFS_IT_" + name);
        if (fromEnv != null && !fromEnv.isBlank()) {
            return fromEnv;
        }
        final String fromProperty = System.getProperty("jcifs.it." + name.toLowerCase(Locale.ROOT).replace('_', '.'));
        if (fromProperty != null && !fromProperty.isBlank()) {
            return fromProperty;
        }
        return fallback;
    }
}
