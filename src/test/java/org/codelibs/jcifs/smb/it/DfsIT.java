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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.it.env.RequiresDfs;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * DFS namespace traversal.
 *
 * <p>
 * The namespace deliberately contains a pair of links whose names share a
 * prefix ({@code link} and {@code link-extra}). Unbounded prefix matching in the
 * referral code has been a recurring defect - #86 and #88 were both instances -
 * so the fixture keeps a permanent trap for it.
 * </p>
 */
@RequiresDfs
class DfsIT extends AbstractSmbIT {

    private SmbFile workDir;

    @AfterEach
    void removeFixtureFile() {
        deleteQuietly(this.workDir);
    }

    private String dfsPath(final String link) {
        return server().url(server().dfsRoot(), link + "/");
    }

    @Test
    @DisplayName("a DFS link resolves to its target share")
    void linkResolvesToItsTarget() throws Exception {
        final CIFSContext context = server().context();
        final String fileName = "dfs-" + UUID.randomUUID() + ".txt";
        final String contents = "reached through the namespace";

        final SmbFile direct = new SmbFile(server().url(server().share(), fileName), context);
        try (OutputStream out = direct.getOutputStream()) {
            out.write(contents.getBytes(StandardCharsets.UTF_8));
        }
        this.workDir = direct;

        try (SmbFile viaDfs = new SmbFile(dfsPath("link") + fileName, context); InputStream in = viaDfs.getInputStream()) {
            assertArrayEquals(contents.getBytes(StandardCharsets.UTF_8), in.readAllBytes());
        }
    }

    @Test
    @DisplayName("a link whose name extends another link's name resolves to its own target")
    void linkWithAnOverlappingPrefixIsNotConfusedWithTheShorterOne() throws Exception {
        final CIFSContext context = server().context();
        final String fileName = "dfs-prefix-" + UUID.randomUUID() + ".txt";

        // The two links point at different shares on purpose, so a file placed in one target is the observable that
        // says which target a link reached. Checking only that both links resolve cannot see the defect this fixture
        // exists to catch: a referral that maps the whole "link-extra" component to "link"'s target reaches a real
        // share, so both links still exist. The narrower form, where "-extra" is left over and appended, was caught
        // before; this covers the form that was not.
        final SmbFile direct = new SmbFile(server().url(server().share(), fileName), context);
        direct.createNewFile();
        this.workDir = direct;

        try (SmbFile shorter = new SmbFile(dfsPath("link"), context); SmbFile longer = new SmbFile(dfsPath("link-extra"), context)) {
            assertTrue(shorter.exists(), "link should resolve");
            assertTrue(longer.exists(), "link-extra should resolve");
        }

        try (SmbFile viaShorter = new SmbFile(dfsPath("link") + fileName, context);
                SmbFile viaLonger = new SmbFile(dfsPath("link-extra") + fileName, context)) {
            assertTrue(viaShorter.exists(), "the file should be reachable through the link pointing at its share");
            assertFalse(viaLonger.exists(), "link-extra points at a different share, so the file must not be reachable through it");
        }
    }

    @Test
    @DisplayName("a link with a dead first target fails over to a live one")
    void deadTargetFailsOver() throws Exception {
        try (SmbFile viaDfs = new SmbFile(dfsPath("multi"), server().context())) {
            assertTrue(viaDfs.exists(), "the namespace should have fallen back to the reachable target");
        }
    }

    @Test
    @DisplayName("a link whose every target is dead reports a failure")
    void deadLinkFails() throws Exception {
        final CIFSContext context = server().context();
        assertThrows(Exception.class, () -> {
            try (SmbFile viaDfs = new SmbFile(dfsPath("broken"), context)) {
                viaDfs.listFiles();
            }
        }, "a link with no reachable target must not silently succeed");
    }
}
