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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.Random;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.impl.SmbNegotiationProbe;
import org.codelibs.jcifs.smb.it.env.RequiresDialect;
import org.codelibs.jcifs.smb.it.env.Smb3Matrix;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * SMB3 transform encryption against a share that mandates it.
 *
 * <p>
 * The server side of this is verified by the preflight check, which refuses to
 * let the suite start unless the encrypted share really does reject a client
 * that cannot encrypt. Without that, every test here would pass against a plain
 * share and prove nothing.
 * </p>
 */
class EncryptionIT extends AbstractSmbIT {

    /** Comfortably larger than a single transform, to exercise splitting. */
    private static final int LARGE_PAYLOAD_BYTES = 3 * 1024 * 1024;

    private SmbFile workDir;

    @AfterEach
    void removeWorkDir() {
        deleteQuietly(this.workDir);
    }

    private static Properties encrypting() {
        final Properties props = new Properties();
        props.setProperty("jcifs.client.encryptionEnabled", "true");
        return props;
    }

    @Test
    @DisplayName("a client that cannot encrypt is refused by the encrypted share")
    void clientWithoutEncryptionIsRefused() throws Exception {
        // Both ends, not just the ceiling: JCIFS_IT_DIALECT pins the floor too and
        // leaving it in place would invert the range.
        final Properties noEncryption = new Properties();
        noEncryption.setProperty("jcifs.client.minVersion", "SMB202");
        noEncryption.setProperty("jcifs.client.maxVersion", "SMB202");
        final CIFSContext context = server().context(noEncryption);

        assertThrows(Exception.class, () -> {
            try (SmbFile share = new SmbFile(server().url(server().encryptedShare()), context)) {
                share.exists();
            }
        }, "the encrypted share must not accept a client that cannot encrypt");
    }

    @Test
    @RequiresDialect(DialectVersion.SMB300)
    @DisplayName("the plain share is still usable with encryption enabled")
    void plainShareWorksWithEncryptionEnabled() throws Exception {
        final CIFSContext context = server().context(encrypting());
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "plain.txt", "written with encryption enabled");
        assertTrue(file.exists());
    }

    @Test
    @RequiresDialect(DialectVersion.SMB300)
    @DisplayName("small payloads round trip through the encrypted share")
    void smallPayloadRoundTrips() throws Exception {
        final CIFSContext context = server().context(encrypting());
        this.workDir = createWorkDir(context, server().encryptedShare());
        final String contents = "encrypted round trip";
        final SmbFile file = writeFile(this.workDir, "small.txt", contents);

        try (InputStream in = file.getInputStream()) {
            assertArrayEquals(contents.getBytes(StandardCharsets.UTF_8), in.readAllBytes());
        }
    }

    @Test
    @RequiresDialect(DialectVersion.SMB300)
    @DisplayName("a payload larger than one transform round trips through the encrypted share")
    void largePayloadRoundTrips() throws Exception {
        final CIFSContext context = server().context(encrypting());
        this.workDir = createWorkDir(context, server().encryptedShare());

        final byte[] payload = new byte[LARGE_PAYLOAD_BYTES];
        new Random(20260910L).nextBytes(payload);

        final SmbFile file = new SmbFile(this.workDir, "large.bin");
        try (OutputStream out = file.getOutputStream()) {
            out.write(payload);
        }
        try (InputStream in = file.getInputStream()) {
            assertArrayEquals(payload, in.readAllBytes(), "the encrypted payload came back different");
        }
    }

    @Test
    @RequiresDialect(DialectVersion.SMB311)
    @DisplayName("each offered SMB 3.1.1 cipher is the one the server actually negotiates, AES-256 included")
    void eachCipherIsNegotiatedAndCarriesData() throws Exception {
        // One cipher per connection, on purpose. A server picks from the client's offer by its own order of
        // preference - measured against this fixture, Samba selects AES-128-GCM whenever it is offered at all,
        // whatever order the client lists - so an arm offering all four would negotiate AES-128-GCM and prove
        // nothing about AES-256. Offering exactly one makes the server's selection the assertion.
        for (final String cipher : new String[] { "AES-128-CCM", "AES-128-GCM", "AES-256-CCM", "AES-256-GCM" }) {
            final Properties props = encrypting();
            props.setProperty("jcifs.client.encryptionCiphers", cipher);
            props.setProperty("jcifs.client.minVersion", DialectVersion.SMB311.name());
            props.setProperty("jcifs.client.maxVersion", DialectVersion.SMB311.name());
            final CIFSContext context = server().context(props);

            this.workDir = createWorkDir(context, server().encryptedShare());
            final String contents = "encrypted round trip under " + cipher;
            final SmbFile file = writeFile(this.workDir, "cipher.txt", contents);

            // The cipher, not just the round trip: reading the payload back succeeds identically under AES-128, so
            // a client that asked for AES-256 and silently fell back would pass a data-only assertion.
            assertEquals(expectedCipherId(cipher), SmbNegotiationProbe.negotiatedCipher(file),
                    "the server should have selected " + cipher + ", the only cipher offered");

            try (InputStream in = file.getInputStream()) {
                assertArrayEquals(contents.getBytes(StandardCharsets.UTF_8), in.readAllBytes(),
                        "the payload came back different under " + cipher);
            }

            deleteQuietly(this.workDir);
            this.workDir = null;
        }
    }

    private static int expectedCipherId(final String cipher) {
        return switch (cipher) {
        case "AES-128-CCM" -> 0x1;
        case "AES-128-GCM" -> 0x2;
        case "AES-256-CCM" -> 0x3;
        case "AES-256-GCM" -> 0x4;
        default -> throw new IllegalArgumentException(cipher);
        };
    }

    @Smb3Matrix
    @DisplayName("a payload round trips through the encrypted share on every SMB3 dialect")
    void payloadRoundTripsOnEverySmb3Dialect(final DialectVersion dialect) throws Exception {
        // 3.0 and 3.0.2 agree the cipher through the negotiate capabilities, while
        // 3.1.1 negotiates it in a context, so a dialect the suite never pins is a
        // dialect whose encryption setup is never proved.
        final Properties props = encrypting();
        props.setProperty("jcifs.client.minVersion", dialect.name());
        props.setProperty("jcifs.client.maxVersion", dialect.name());
        final CIFSContext context = server().context(props);

        this.workDir = createWorkDir(context, server().encryptedShare());
        final String contents = "encrypted round trip on " + dialect;
        final SmbFile file = writeFile(this.workDir, "dialect.txt", contents);

        try (InputStream in = file.getInputStream()) {
            assertArrayEquals(contents.getBytes(StandardCharsets.UTF_8), in.readAllBytes(),
                    "the encrypted payload came back different on " + dialect);
        }
    }
}
