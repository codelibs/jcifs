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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.impl.DosFileFilter;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.it.env.DialectMatrix;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Wildcards and filters, which the server applies rather than the client.
 *
 * <p>
 * {@code DirFileEntryEnumIterator2} puts the wildcard into the SMB2
 * QUERY_DIRECTORY request, so {@code listFiles("*.txt")} is a question asked of
 * the server and answered by its own name matcher. A {@link DosFileFilter} goes
 * further and replaces the search attributes too. The suite only ever listed a
 * directory whole, so none of that had been sent to a server.
 * </p>
 */
class EnumerationFilterIT extends AbstractSmbIT {

    private SmbFile workDir;

    @BeforeEach
    void createFixture() throws Exception {
        this.workDir = createWorkDir(server().context(), server().share());
        writeFile(this.workDir, "alpha.txt", "alpha");
        writeFile(this.workDir, "beta.txt", "beta");
        writeFile(this.workDir, "gamma.dat", "gamma");
        new SmbFile(this.workDir, "subdir/").mkdirs();
    }

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

    private static Set<String> namesOf(final SmbFile[] files) {
        return Arrays.stream(files).map(SmbFile::getName).collect(Collectors.toSet());
    }

    @DialectMatrix
    @DisplayName("an extension wildcard is matched by the server")
    void extensionWildcardIsMatchedByTheServer(final DialectVersion dialect) throws Exception {
        final CIFSContext context = contextFor(dialect);
        try (SmbFile dir = new SmbFile(this.workDir.getLocator().getURL().toString(), context)) {
            final Set<String> matched = namesOf(dir.listFiles("*.txt"));
            assertEquals(Set.of("alpha.txt", "beta.txt"), matched, "the server should have matched only the .txt files");
        }
    }

    @Test
    @DisplayName("a single-character wildcard is matched by the server")
    void singleCharacterWildcardIsMatchedByTheServer() throws Exception {
        final Set<String> matched = namesOf(this.workDir.listFiles("?eta.txt"));
        assertEquals(Set.of("beta.txt"), matched, "'?' should stand for exactly one character");
    }

    @Test
    @DisplayName("a wildcard that matches nothing returns an empty listing")
    void wildcardThatMatchesNothingReturnsEmpty() throws Exception {
        assertEquals(0, this.workDir.listFiles("*.nosuchextension").length, "a wildcard matching nothing should return no entries");
    }

    @Test
    @DisplayName("a name filter is applied on top of the listing")
    void nameFilterIsApplied() throws Exception {
        final Set<String> matched = namesOf(this.workDir.listFiles((parent, name) -> name.startsWith("a")));
        assertEquals(Set.of("alpha.txt"), matched, "only the entry the filter accepted should come back");
    }

    @Test
    @DisplayName("a resource filter sees directories as well as files")
    void resourceFilterSeesDirectories() throws Exception {
        final Set<String> directories = namesOf(this.workDir.listFiles(file -> file.isDirectory()));
        assertEquals(Set.of("subdir/"), directories, "the filter should have been offered the subdirectory");
    }

    @Test
    @DisplayName("a DosFileFilter restricted to directories returns only directories")
    void dosFileFilterRestrictedToDirectories() throws Exception {
        final Set<String> matched = namesOf(this.workDir.listFiles(new DosFileFilter("*", SmbConstants.ATTR_DIRECTORY)));
        assertTrue(matched.contains("subdir/"), "the subdirectory should have been returned, got " + matched);
        assertFalse(matched.contains("alpha.txt"), "a plain file should not have been returned, got " + matched);
    }

    @Test
    @DisplayName("listing without a wildcard returns everything")
    void listingWithoutAWildcardReturnsEverything() throws Exception {
        final Set<String> all = namesOf(this.workDir.listFiles());
        assertEquals(Set.of("alpha.txt", "beta.txt", "gamma.dat", "subdir/"), all, "an unfiltered listing should return every entry");
    }
}
