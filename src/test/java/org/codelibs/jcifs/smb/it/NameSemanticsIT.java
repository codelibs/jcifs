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
import java.nio.charset.StandardCharsets;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.impl.NtStatus;
import org.codelibs.jcifs.smb.impl.SmbException;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.it.env.RequiresBackend;
import org.codelibs.jcifs.smb.it.env.SmbBackend;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Names the two servers treat differently, and one place they agree by surprise.
 *
 * <p>
 * {@code SpecialNamesIT} covers names that go through. This covers the ones that
 * do not, and the ones that go through on one backend only - the client passes
 * the name to the server unchanged, so what happens next is the server's rule,
 * and a caller writing portable code needs to know which rules differ.
 * </p>
 */
class NameSemanticsIT extends AbstractSmbIT {

    private SmbFile workDir;

    @AfterEach
    void removeWorkDir() throws Exception {
        if (this.workDir != null) {
            try {
                for (final SmbFile child : this.workDir.listFiles()) {
                    deleteQuietly(child);
                }
            } catch (final Exception e) {
                // fall through to removing the directory itself
            }
            deleteQuietly(this.workDir);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = { "CON", "NUL", "PRN", "AUX", "COM1", "LPT1" })
    @RequiresBackend(SmbBackend.WINDOWS)
    @DisplayName("Windows refuses a reserved device name")
    void windowsRefusesAReservedDeviceName(final String name) throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());

        final SmbFile file = new SmbFile(this.workDir, name);
        final SmbException e =
                assertThrows(SmbException.class, file::createNewFile, name + " is a reserved device name and Windows should refuse it");
        assertEquals(NtStatus.NT_STATUS_ACCESS_DENIED, e.getNtStatus(),
                "unexpected status for " + name + ": 0x" + Integer.toHexString(e.getNtStatus()));
    }

    @ParameterizedTest
    @ValueSource(strings = { "CON", "NUL", "PRN", "AUX", "COM1", "LPT1" })
    @RequiresBackend(SmbBackend.SAMBA)
    @DisplayName("Samba accepts a name Windows reserves")
    void sambaAcceptsANameWindowsReserves(final String name) throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());

        final SmbFile file = writeFile(this.workDir, name, "payload");
        assertTrue(file.exists(), name + " should be an ordinary file name on a POSIX server");
        try (InputStream in = file.getInputStream()) {
            assertArrayEquals("payload".getBytes(StandardCharsets.UTF_8), in.readAllBytes());
        }
    }

    @Test
    @DisplayName("a name ending in a dot is accepted by both servers")
    void nameEndingInADotIsAccepted() throws Exception {
        // Worth pinning because it contradicts the usual expectation: the Win32 API
        // strips a trailing dot, but the SMB server does not, so the name survives
        // the round trip on Windows just as it does on Samba. The MS-DOS device
        // names are the ones that genuinely differ.
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());

        final SmbFile file = writeFile(this.workDir, "trailing.", "payload");
        assertTrue(file.exists(), "a trailing dot should survive the round trip");
        try (InputStream in = file.getInputStream()) {
            assertArrayEquals("payload".getBytes(StandardCharsets.UTF_8), in.readAllBytes());
        }
    }

    @Test
    @DisplayName("a name ending in a space is accepted by both servers")
    void nameEndingInASpaceIsAccepted() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());

        final SmbFile file = writeFile(this.workDir, "trailing ", "payload");
        assertTrue(file.exists(), "a trailing space should survive the round trip");
        try (InputStream in = file.getInputStream()) {
            assertArrayEquals("payload".getBytes(StandardCharsets.UTF_8), in.readAllBytes());
        }
    }

    @Test
    @DisplayName("a file written in one case is found in another")
    void fileWrittenInOneCaseIsFoundInAnother() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());

        writeFile(this.workDir, "MixedCase.TXT", "payload");

        final SmbFile lowered = new SmbFile(this.workDir, "mixedcase.txt");
        assertTrue(lowered.exists(), "both servers match names without regard to case");
        try (InputStream in = lowered.getInputStream()) {
            assertArrayEquals("payload".getBytes(StandardCharsets.UTF_8), in.readAllBytes(),
                    "the differently cased lookup should reach the same file");
        }
    }

    @Test
    @DisplayName("a listing reports the case the file was created with")
    void listingReportsTheCreatedCase() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        writeFile(this.workDir, "PreservedCase.TXT", "payload");

        final SmbFile[] children = this.workDir.listFiles();
        assertEquals(1, children.length, "the work directory should hold exactly the one file");
        assertEquals("PreservedCase.TXT", children[0].getName(), "matching without regard to case does not mean the stored case is lost");
    }
}
