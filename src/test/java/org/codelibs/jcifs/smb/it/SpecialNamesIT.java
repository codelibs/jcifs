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
import java.util.Arrays;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.SmbResource;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * File names that are legal on SMB but awkward in a URL.
 */
class SpecialNamesIT extends AbstractSmbIT {

    private SmbFile workDir;

    @AfterEach
    void removeWorkDir() throws Exception {
        if (this.workDir != null) {
            try {
                final SmbResource[] children = this.workDir.listFiles();
                if (children != null) {
                    for (final SmbResource child : children) {
                        deleteQuietly((SmbFile) child);
                    }
                }
            } catch (final Exception e) {
                // fall through to removing the directory itself
            }
            deleteQuietly(this.workDir);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = { "日本語ファイル.txt", "with space.txt", "with+plus.txt", "with&amp.txt", "with~tilde.txt", "with'apostrophe.txt",
            "UPPER and lower.TXT" })
    @DisplayName("a file with an awkward name round trips")
    void awkwardNameRoundTrips(final String name) throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());

        final String contents = "contents of " + name;
        final SmbFile file = writeFile(this.workDir, name, contents);

        assertTrue(file.exists(), name + " was written but does not exist");
        try (InputStream in = file.getInputStream()) {
            assertArrayEquals(contents.getBytes(StandardCharsets.UTF_8), in.readAllBytes());
        }
    }

    @Test
    @DisplayName("an awkward name survives a directory listing")
    void awkwardNameSurvivesListing() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final String name = "日本語 and space.txt";
        writeFile(this.workDir, name, "listed");

        final SmbResource[] children = this.workDir.listFiles();
        assertTrue(Arrays.stream(children).anyMatch(child -> name.equals(child.getName())),
                "listing did not contain " + name + ", it had " + Arrays.stream(children).map(SmbResource::getName).toList());
    }

    @Test
    @DisplayName("a long name is accepted up to the SMB limit")
    void longNameIsAccepted() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final String name = "l".repeat(200) + ".txt";
        final SmbFile file = writeFile(this.workDir, name, "long");
        assertTrue(file.exists());
    }
}
