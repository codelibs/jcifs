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

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.UUID;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.impl.SmbNegotiationProbe;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Checks that the server really is configured the way the tests assume, before
 * a single test runs.
 *
 * <p>
 * Every check here exists because its absence produces a green run that proves
 * nothing: an encryption test that silently ran against a plain share, or a
 * dialect test whose configuration property was never read.
 * </p>
 */
final class SmbItPreflight {

    private static final Logger log = LoggerFactory.getLogger(SmbItPreflight.class);

    private static final int CONNECT_TIMEOUT_MILLIS = 5000;
    private static final int REACHABILITY_ATTEMPTS = 60;
    private static final long REACHABILITY_INTERVAL_MILLIS = 500;

    private SmbItPreflight() {
    }

    static void check(final SmbServerFixture fixture) throws Exception {
        awaitReachable(fixture);
        checkPlainShareIsWritable(fixture);
        checkEncryptedShareRejectsUnencryptedClients(fixture);
        checkDialectSettingIsHonoured(fixture);
        checkDfsAvailability(fixture);
        logNegotiatedState(fixture);
    }

    /**
     * Polls until the port accepts connections. This replaces a fixed sleep: the
     * server is ready when it answers, not after an arbitrary number of seconds.
     */
    private static void awaitReachable(final SmbServerFixture fixture) throws Exception {
        Exception last = null;
        for (int attempt = 0; attempt < REACHABILITY_ATTEMPTS; attempt++) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(fixture.host(), fixture.port()), CONNECT_TIMEOUT_MILLIS);
                return;
            } catch (final Exception e) {
                last = e;
                Thread.sleep(REACHABILITY_INTERVAL_MILLIS);
            }
        }
        throw new IllegalStateException("SMB server at " + fixture.host() + ":" + fixture.port() + " never became reachable", last);
    }

    private static void checkPlainShareIsWritable(final SmbServerFixture fixture) throws Exception {
        final String name = "preflight-" + UUID.randomUUID() + ".txt";
        final CIFSContext context = fixture.context();
        try (SmbFile file = new SmbFile(fixture.url(fixture.share(), name), context)) {
            try (OutputStream out = file.getOutputStream()) {
                out.write("preflight".getBytes(StandardCharsets.UTF_8));
            }
            if (!file.exists()) {
                throw new IllegalStateException("Wrote to " + file.getPath() + " but the file does not exist");
            }
            file.delete();
        }
    }

    /**
     * The encrypted share must actually mandate encryption. An SMB 2.0.2 client
     * cannot encrypt at all, so it is the cleanest probe: it must be refused
     * there and accepted on the plain share.
     */
    private static void checkEncryptedShareRejectsUnencryptedClients(final SmbServerFixture fixture) throws Exception {
        // Both ends of the range, not just the ceiling: JCIFS_IT_DIALECT pins the
        // floor too, and leaving it in place would invert the range.
        final Properties noEncryption = new Properties();
        noEncryption.setProperty("jcifs.client.minVersion", "SMB202");
        noEncryption.setProperty("jcifs.client.maxVersion", "SMB202");
        final CIFSContext context = fixture.context(noEncryption);

        try (SmbFile control = new SmbFile(fixture.url(fixture.share()), context)) {
            if (!control.exists()) {
                throw new IllegalStateException("An SMB 2.0.2 client cannot reach the plain share " + fixture.share()
                        + "; the encryption probe below would be meaningless");
            }
        }

        boolean refused = false;
        try (SmbFile encrypted = new SmbFile(fixture.url(fixture.encryptedShare()), context)) {
            encrypted.exists();
        } catch (final Exception e) {
            refused = true;
            log.debug("Encrypted share correctly refused an unencrypted client", e);
        }
        if (!refused) {
            throw new IllegalStateException("Share " + fixture.encryptedShare() + " accepted a client that cannot encrypt. "
                    + "It is not configured to require encryption, so the encryption tests would prove nothing.");
        }
    }

    /**
     * Self-test of the harness. The {@code jcifs.smb.client.} prefix was renamed
     * in 3.0.0 and the old names are read back as defaults, so a test can pin a
     * dialect, be silently ignored and still pass. Pin one and check the wire.
     */
    private static void checkDialectSettingIsHonoured(final SmbServerFixture fixture) throws Exception {
        final Properties pinned = new Properties();
        pinned.setProperty("jcifs.client.minVersion", "SMB210");
        pinned.setProperty("jcifs.client.maxVersion", "SMB210");
        try (SmbFile file = new SmbFile(fixture.url(fixture.share()), fixture.context(pinned))) {
            final DialectVersion negotiated = SmbNegotiationProbe.negotiatedDialect(file);
            if (negotiated != DialectVersion.SMB210) {
                throw new IllegalStateException("Pinned jcifs.client.maxVersion=SMB210 but negotiated " + negotiated
                        + ". The configuration property is not being honoured, so no dialect-dependent test can be trusted.");
            }
        }
    }

    /**
     * When CI demands that the tests actually run, a server that cannot serve DFS
     * is a misconfiguration rather than a reason to skip the DFS tests.
     */
    private static void checkDfsAvailability(final SmbServerFixture fixture) throws Exception {
        if (!fixture.dfsAvailable()) {
            if (SmbServerResolver.required()) {
                throw new IllegalStateException("SMB integration tests are required but the server answers on port " + fixture.port()
                        + " rather than 445, so DFS referrals cannot be followed and the DFS tests would silently skip.");
            }
            log.info("Server is on port {}, DFS tests will skip", fixture.port());
            return;
        }
        try (SmbFile root = new SmbFile(fixture.url(fixture.dfsRoot()), fixture.context())) {
            if (!root.exists()) {
                throw new IllegalStateException("DFS root " + fixture.dfsRoot() + " is not reachable");
            }
        }
    }

    private static void logNegotiatedState(final SmbServerFixture fixture) throws Exception {
        try (SmbFile file = new SmbFile(fixture.url(fixture.share()), fixture.context())) {
            log.info("Negotiated dialect={} signing={} against {}", SmbNegotiationProbe.negotiatedDialect(file),
                    SmbNegotiationProbe.signingNegotiated(file), fixture);
        }
    }
}
