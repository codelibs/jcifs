/*
 * © 2026 CodeLibs, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.codelibs.jcifs.smb.it;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.it.env.RequiresBackend;
import org.codelibs.jcifs.smb.it.env.SmbBackend;
import org.codelibs.jcifs.smb.it.env.SmbServerResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.Container;

/**
 * {@link SmbFile#changeTime()} against a real server.
 *
 * <p>
 * The point of the change time is that it moves when only the metadata of a file changes - its DACL in particular -
 * while the last write time stays where it was. Whether it does is the server's decision, and the two backends decide
 * differently: NTFS moves it, Samba reports the last write time in its place. Each backend gets its own test.
 * </p>
 */
class ChangeTimeIT extends AbstractSmbIT {

    private static final Logger log = LoggerFactory.getLogger(ChangeTimeIT.class);

    private static final String FILE_NAME = "change-time.txt";

    /** Where build_helpers/win-setup.ps1 puts the plain share on the Windows runner. */
    private static final Path WINDOWS_SHARE_PATH = Path.of("C:\\smbit\\share");

    /** Where build_helpers/samba/entrypoint.sh puts the plain share in the container. */
    private static final String SAMBA_SHARE_PATH = "/srv/share/";

    /**
     * Long enough for any server's timestamp resolution to tell a later change apart from the write.
     */
    private static final long SETTLE_MILLIS = 1100L;

    private SmbFile workDir;

    @AfterEach
    void removeWorkDir() {
        deleteQuietly(this.workDir);
    }

    @Test
    @DisplayName("a written file reports a change time next to its last write time, also when listed")
    void writtenFileReportsChangeTime() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        writeFile(this.workDir, FILE_NAME, "contents");

        try (SmbFile file = new SmbFile(this.workDir, FILE_NAME)) {
            final long lastModified = file.lastModified();
            final long changeTime = file.changeTime();
            log.info("written file: lastModified={} changeTime={}", lastModified, changeTime);

            assertTrue(changeTime > 0L, "the server should report a change time, was " + changeTime);
            assertTrue(Math.abs(changeTime - lastModified) <= 5000L,
                    "a file just written should have changed when it was written: lastModified=" + lastModified + " changeTime="
                            + changeTime);

            try (SmbFile listed = listed(this.workDir, FILE_NAME)) {
                assertEquals(changeTime, listed.changeTime(), "the listing should report the same change time");
                assertEquals(lastModified, listed.lastModified(), "the listing should report the same last write time");
            }
        }
    }

    @Test
    @RequiresBackend(SmbBackend.WINDOWS)
    @DisplayName("NTFS moves the change time, and not the last write time, when the DACL changes")
    void ntfsMovesChangeTimeOnDaclChange() throws Exception {
        assumeTrue(Files.isDirectory(WINDOWS_SHARE_PATH),
                "Skipping: the DACL is changed on the server's disk, which is only reachable on the runner that hosts the share");
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        writeFile(this.workDir, FILE_NAME, "contents");

        final long lastModifiedBefore;
        final long changeTimeBefore;
        final String relative;
        try (SmbFile before = new SmbFile(this.workDir, FILE_NAME)) {
            lastModifiedBefore = before.lastModified();
            changeTimeBefore = before.changeTime();
            relative = before.getUncPath().substring(1);
        }

        Thread.sleep(SETTLE_MILLIS);
        final Process icacls = new ProcessBuilder("icacls", WINDOWS_SHARE_PATH.resolve(relative).toString(), "/grant",
                SmbServerResolver.secondaryUser() + ":(R)").redirectErrorStream(true).start();
        final String output;
        try (InputStream in = icacls.getInputStream()) {
            output = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        assertEquals(0, icacls.waitFor(), "icacls failed: " + output);

        assertDaclChangedOnlyMetadata(lastModifiedBefore, changeTimeBefore, true);
    }

    @Test
    @RequiresBackend(SmbBackend.SAMBA)
    @DisplayName("Samba reports the last write time as the change time, so a DACL change does not move it")
    void sambaKeepsChangeTimeOnDaclChange() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        writeFile(this.workDir, FILE_NAME, "contents");

        final long lastModifiedBefore;
        final long changeTimeBefore;
        final String relative;
        try (SmbFile before = new SmbFile(this.workDir, FILE_NAME)) {
            lastModifiedBefore = before.lastModified();
            changeTimeBefore = before.changeTime();
            relative = before.getUncPath().substring(1).replace('\\', '/');
        }
        assertEquals(lastModifiedBefore, changeTimeBefore, "Samba sends st_mtime as both the last write and the change time");
        final String posixPath = SAMBA_SHARE_PATH + relative;
        final String ctimeBefore = posixChangeTime(posixPath);

        Thread.sleep(SETTLE_MILLIS);
        // Changed over SMB by the file's owner, the way an administrator would, rather than on the disk below Samba.
        final Container.ExecResult smbcacls = SmbServerResolver.execInSamba("smbcacls", "//127.0.0.1/" + server().share(), relative, "-U",
                server().user() + "%" + server().password(), "-a", "ACL:" + SmbServerResolver.secondaryUser() + ":ALLOWED/0x0/READ");
        assertEquals(0, smbcacls.getExitCode(), "smbcacls failed: " + smbcacls.getStdout() + smbcacls.getStderr());

        final String ctimeAfter = posixChangeTime(posixPath);
        log.info("posix ctime before={} after={}", ctimeBefore, ctimeAfter);
        assertNotEquals(ctimeBefore, ctimeAfter, "the DACL change should have moved the file's POSIX ctime");

        assertDaclChangedOnlyMetadata(lastModifiedBefore, changeTimeBefore, false);
    }

    /**
     * Checks a fresh handle and a listing after the DACL of the test file gained an entry for the secondary user.
     *
     * @param changeTimeMoves whether the server is expected to move the change time
     */
    private void assertDaclChangedOnlyMetadata(final long lastModifiedBefore, final long changeTimeBefore, final boolean changeTimeMoves)
            throws Exception {
        try (SmbFile after = new SmbFile(this.workDir, FILE_NAME)) {
            assertTrue(
                    Arrays.stream(after.getSecurity(true))
                            .anyMatch(ace -> ace.getSID() != null
                                    && SmbServerResolver.secondaryUser().equalsIgnoreCase(ace.getSID().getAccountName())),
                    "the DACL should now name " + SmbServerResolver.secondaryUser() + ": " + Arrays.toString(after.getSecurity(true)));

            final long lastModifiedAfter = after.lastModified();
            final long changeTimeAfter = after.changeTime();
            log.info("DACL change: lastModified {} -> {}, changeTime {} -> {}", lastModifiedBefore, lastModifiedAfter, changeTimeBefore,
                    changeTimeAfter);

            assertEquals(lastModifiedBefore, lastModifiedAfter, "a DACL change must not move the last write time");
            if (changeTimeMoves) {
                assertTrue(changeTimeAfter > changeTimeBefore,
                        "the DACL change should have moved the change time: before=" + changeTimeBefore + " after=" + changeTimeAfter);
            } else {
                assertEquals(changeTimeBefore, changeTimeAfter, "the change time moved although the server reports the last write time");
            }

            try (SmbFile listed = listed(this.workDir, FILE_NAME)) {
                assertEquals(changeTimeAfter, listed.changeTime(), "the listing should report the same change time");
                assertEquals(lastModifiedBefore, listed.lastModified(), "the listing should report the same last write time");
            }
        }
    }

    private static String posixChangeTime(final String path) throws Exception {
        final Container.ExecResult stat = SmbServerResolver.execInSamba("stat", "-c", "%z", path);
        assertEquals(0, stat.getExitCode(), "stat failed: " + stat.getStderr());
        return stat.getStdout().trim();
    }

    private static SmbFile listed(final SmbFile dir, final String name) throws Exception {
        SmbFile found = null;
        for (final SmbFile child : dir.listFiles()) {
            if (found == null && name.equals(child.getName())) {
                found = child;
            } else {
                child.close();
            }
        }
        assertTrue(found != null, "the listing did not contain " + name);
        return found;
    }
}
