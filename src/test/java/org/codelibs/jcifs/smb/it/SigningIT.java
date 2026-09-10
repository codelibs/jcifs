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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.impl.SmbNegotiationProbe;
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
}
