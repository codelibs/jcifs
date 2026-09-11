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

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Resolving a child against a parent, with and without a trailing separator.
 *
 * <p>
 * A parent given without a trailing slash used to glue the child name onto the
 * last path segment, and the URL, the canonical path and the UNC path each broke
 * differently (#83). These tests hold all three to the same answer against a
 * live server.
 * </p>
 */
class ResolveIT extends AbstractSmbIT {

    private SmbFile workDir;

    @AfterEach
    void removeWorkDir() throws Exception {
        if (this.workDir != null) {
            try (SmbFile child = new SmbFile(this.workDir, "child.txt")) {
                deleteQuietly(child);
            }
            deleteQuietly(this.workDir);
        }
    }

    @Test
    @DisplayName("a child resolves under a parent given without a trailing separator")
    void childResolvesUnderParentWithoutTrailingSeparator() throws Exception {
        final CIFSContext context = server().context();
        final String dirName = "resolve-" + UUID.randomUUID();

        this.workDir = new SmbFile(server().url(server().share(), dirName + "/"), context);
        this.workDir.mkdirs();
        writeFile(this.workDir, "child.txt", "child contents");

        try (SmbFile parentWithoutSlash = new SmbFile(server().url(server().share(), dirName), context);
                SmbFile child = new SmbFile(parentWithoutSlash, "child.txt")) {
            assertTrue(child.exists(), "child resolved to " + child.getPath() + ", which does not exist");
            assertTrue(child.getPath().endsWith("/" + dirName + "/child.txt"), "unexpected URL path: " + child.getPath());
            assertTrue(child.getUncPath().endsWith("\\" + dirName + "\\child.txt"), "unexpected UNC path: " + child.getUncPath());
            assertTrue(child.getCanonicalPath().endsWith("/" + dirName + "/child.txt"),
                    "unexpected canonical path: " + child.getCanonicalPath());
        }
    }

    @Test
    @DisplayName("a trailing separator on the parent makes no difference")
    void trailingSeparatorOnParentMakesNoDifference() throws Exception {
        final CIFSContext context = server().context();
        final String dirName = "resolve-" + UUID.randomUUID();

        this.workDir = new SmbFile(server().url(server().share(), dirName + "/"), context);
        this.workDir.mkdirs();
        writeFile(this.workDir, "child.txt", "child contents");

        try (SmbFile withSlash = new SmbFile(server().url(server().share(), dirName + "/"), context);
                SmbFile withoutSlash = new SmbFile(server().url(server().share(), dirName), context);
                SmbFile fromWithSlash = new SmbFile(withSlash, "child.txt");
                SmbFile fromWithoutSlash = new SmbFile(withoutSlash, "child.txt")) {
            assertTrue(fromWithSlash.exists());
            assertTrue(fromWithoutSlash.exists());
            assertTrue(fromWithSlash.getUncPath().equals(fromWithoutSlash.getUncPath()),
                    "UNC paths diverged: " + fromWithSlash.getUncPath() + " vs " + fromWithoutSlash.getUncPath());
        }
    }
}
