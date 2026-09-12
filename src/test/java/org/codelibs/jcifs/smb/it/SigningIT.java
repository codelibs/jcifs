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
package org.codelibs.jcifs.smb.it;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Properties;
import java.util.Random;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.impl.SmbNegotiationProbe;
import org.codelibs.jcifs.smb.it.env.DialectMatrix;
import org.codelibs.jcifs.smb.it.env.RequiresDialect;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Message signing against a real server.
 *
 * <p>
 * Both backends are configured to require signing - Windows Server 2025 does so
 * by default and the Samba fixture is set to {@code server signing = mandatory}
 * to match - so every connection here is signed and the tests are the same on
 * both.
 * </p>
 *
 * <p>
 * Note what {@code isSigningNegotiated()} actually reports: it reads the
 * SIGNING_REQUIRED bit out of the server's negotiate response. It says the server
 * demanded signing, not that the client signed anything - {@code SmbTreeHandle}
 * exposes no stronger observation.
 * </p>
 */
class SigningIT extends AbstractSmbIT {

    private SmbFile workDir;

    @AfterEach
    void removeWorkDir() {
        deleteQuietly(this.workDir);
    }

    @Test
    @DisplayName("the server advertises that signing is required")
    void serverRequiresSigning() throws Exception {
        try (SmbFile file = new SmbFile(server().url(server().share()), server().context())) {
            assertTrue(SmbNegotiationProbe.signingNegotiated(file), "the test server should be configured to require signing");
        }
    }

    @Test
    @DisplayName("file contents survive a signed session")
    void payloadRoundTripsAgainstASigningServer() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final String contents = "signed round trip";
        final SmbFile file = writeFile(this.workDir, "signed.txt", contents);

        try (InputStream in = file.getInputStream()) {
            assertArrayEquals(contents.getBytes(StandardCharsets.UTF_8), in.readAllBytes());
        }
    }

    @Test
    @DisplayName("a client that enforces signing can still talk to a server that requires it")
    void clientEnforcedSigningWorks() throws Exception {
        final Properties props = new Properties();
        props.setProperty("jcifs.client.signingEnforced", "true");
        final CIFSContext context = server().context(props);
        this.workDir = createWorkDir(context, server().share());
        final String contents = "client enforced signing";
        final SmbFile file = writeFile(this.workDir, "enforced.txt", contents);

        try (InputStream in = file.getInputStream()) {
            assertArrayEquals(contents.getBytes(StandardCharsets.UTF_8), in.readAllBytes());
        }
    }

    @Test
    @RequiresDialect(DialectVersion.SMB311)
    @DisplayName("each offered SMB 3.1.1 signing algorithm is the one the server negotiates, GMAC included")
    void eachSigningAlgorithmIsNegotiatedAndCarriesData() throws Exception {
        // One algorithm per connection, for the same reason the cipher arms do it: a server chooses from the
        // client's offer by its own preference - this fixture lists AES-128-GMAC first - so an arm offering
        // several would say nothing about which one the client can actually drive. Offering exactly one makes the
        // server's selection the assertion.
        for (final String algorithm : new String[] { "AES-CMAC", "AES-GMAC" }) {
            final Properties props = new Properties();
            props.setProperty("jcifs.client.signingAlgorithms", algorithm);
            props.setProperty("jcifs.client.signingEnforced", "true");
            props.setProperty("jcifs.client.minVersion", DialectVersion.SMB311.name());
            props.setProperty("jcifs.client.maxVersion", DialectVersion.SMB311.name());
            final CIFSContext context = server().context(props);

            this.workDir = createWorkDir(context, server().share());

            assertEquals(expectedSigningAlgorithmId(algorithm), SmbNegotiationProbe.negotiatedSigningAlgorithm(this.workDir),
                    "the server should have selected " + algorithm + ", the only algorithm offered");

            // Several messages, because the GMAC nonce is derived per message from the message id: signing one
            // message proves the algorithm was accepted, but not that a session can keep using it.
            final String contents = "signed with " + algorithm;
            for (int i = 0; i < 3; i++) {
                final SmbFile file = writeFile(this.workDir, "algo-" + i + ".txt", contents + " #" + i);
                try (InputStream in = file.getInputStream()) {
                    assertArrayEquals((contents + " #" + i).getBytes(StandardCharsets.UTF_8), in.readAllBytes(),
                            "payload " + i + " came back different under " + algorithm);
                }
            }

            // Enumeration, which keeps issuing signed requests against one handle.
            assertEquals(3, this.workDir.list().length, "every signed file should be listed under " + algorithm);

            deleteQuietly(this.workDir);
            this.workDir = null;
        }
    }

    private static int expectedSigningAlgorithmId(final String algorithm) {
        return switch (algorithm) {
        case "HMAC-SHA256" -> 0x0;
        case "AES-CMAC" -> 0x1;
        case "AES-GMAC" -> 0x2;
        default -> throw new IllegalArgumentException(algorithm);
        };
    }

    @DialectMatrix
    @DisplayName("signing holds across a whole sequence of requests, on every dialect")
    void signingHoldsAcrossASequenceOfRequests(final DialectVersion dialect) throws Exception {
        // One signing implementation serves every dialect - HMAC-SHA256 below SMB3, AES-128-CMAC at SMB3 and
        // above - so a change to it can break a dialect the suite never pins. Before this, every signing test ran
        // on whatever the suite negotiated, which is 3.1.1: SMB 2.0.2 and 3.0.2 signing were not exercised at all.
        final Properties props = new Properties();
        props.setProperty("jcifs.client.minVersion", dialect.name());
        props.setProperty("jcifs.client.maxVersion", dialect.name());
        props.setProperty("jcifs.client.signingEnforced", "true");
        final CIFSContext context = server().context(props);

        this.workDir = createWorkDir(context, server().share());
        assertEquals(dialect, SmbNegotiationProbe.negotiatedDialect(this.workDir), "the run should have pinned " + dialect);

        // A sequence, not a single exchange. The signature of each message is computed over its own header, and a
        // per-message input that a signing change could get wrong - the message id, say - only shows up once
        // several messages with different ids have gone by. A lone round trip is a weak probe for that.
        final String contents = "signed sequence on " + dialect;
        for (int i = 0; i < 5; i++) {
            final SmbFile file = writeFile(this.workDir, "seq-" + i + ".txt", contents + " #" + i);
            try (InputStream in = file.getInputStream()) {
                assertArrayEquals((contents + " #" + i).getBytes(StandardCharsets.UTF_8), in.readAllBytes(),
                        "signed payload " + i + " came back different on " + dialect);
            }
        }

        // Enumeration issues its own signed requests and is the one operation whose open handle is the iteration,
        // so a signature failure part way through surfaces here rather than on the first message.
        final String[] names = this.workDir.list();
        assertEquals(5, names.length, "every signed file should be listed on " + dialect + ", got " + Arrays.toString(names));
    }

    @DialectMatrix
    @DisplayName("a compounded request chain verifies on every dialect")
    void compoundedChainIsSignedCorrectly(final DialectVersion dialect) throws Exception {
        // exists()/length() on a missing path go out as a compound (related) open+query+close chain, which is
        // signed as one message from the first header. MS-SMB2 3.1.4.1 requires any trailing padding in a chain to
        // be part of the hash, so a chain is the case where a signing change can get the authenticated extent
        // wrong while single messages still verify.
        final Properties props = new Properties();
        props.setProperty("jcifs.client.minVersion", dialect.name());
        props.setProperty("jcifs.client.maxVersion", dialect.name());
        props.setProperty("jcifs.client.signingEnforced", "true");
        final CIFSContext context = server().context(props);

        this.workDir = createWorkDir(context, server().share());
        final SmbFile present = writeFile(this.workDir, "compound.txt", "compound chain");
        assertTrue(present.exists(), "a file just written must be reported as present on " + dialect);
        assertEquals(14, present.length(), "the compounded query should report the written length on " + dialect);

        // And the error path. Verification of an error response is skipped unless requireSecureNegotiate is set
        // (ServerMessageBlock2Response.verifySignature), so a signing fault can hide there while every successful
        // response still verifies. Asking for a path that does not exist is the cheapest way through it.
        try (SmbFile missing = new SmbFile(this.workDir, "no-such-file.txt")) {
            assertFalse(missing.exists(), "a path that was never created must not be reported as present on " + dialect);
        }
    }

    @DialectMatrix
    @DisplayName("a payload spanning many messages stays signed end to end")
    void largePayloadStaysSigned(final DialectVersion dialect) throws Exception {
        // Large transfers are split into many requests, each signed with its own message id, and above SMB 2.1
        // each one spends several credits. This is the broadest sweep over per-message signing state that can be
        // arranged without reaching into the transport.
        final Properties props = new Properties();
        props.setProperty("jcifs.client.minVersion", dialect.name());
        props.setProperty("jcifs.client.maxVersion", dialect.name());
        props.setProperty("jcifs.client.signingEnforced", "true");
        final CIFSContext context = server().context(props);

        this.workDir = createWorkDir(context, server().share());

        final byte[] payload = new byte[3 * 1024 * 1024];
        new Random(20260912L).nextBytes(payload);

        final SmbFile file = new SmbFile(this.workDir, "large-signed.bin");
        try (OutputStream out = file.getOutputStream()) {
            out.write(payload);
        }
        try (InputStream in = file.getInputStream()) {
            assertArrayEquals(payload, in.readAllBytes(), "the signed payload came back different on " + dialect);
        }
    }
}
