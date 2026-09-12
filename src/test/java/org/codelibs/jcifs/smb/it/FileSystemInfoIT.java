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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.it.env.DialectMatrix;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Volume and object information queried from the server.
 *
 * <p>
 * {@code getDiskFreeSpace} is the only caller of the filesystem information
 * classes and {@code fileIndex} the only caller of FILE_INTERNAL_INFO; neither
 * had an integration test, so a change to either info class would have been
 * caught only by a unit test asserting its own encoding.
 * </p>
 */
class FileSystemInfoIT extends AbstractSmbIT {

    private SmbFile workDir;

    @AfterEach
    void removeWorkDir() {
        deleteQuietly(this.workDir);
    }

    @DialectMatrix
    @DisplayName("a share reports its free space")
    void shareReportsItsFreeSpace(final DialectVersion dialect) throws Exception {
        final CIFSContext context = contextFor(dialect);
        try (SmbFile share = new SmbFile(server().url(server().share()), context)) {
            final long free = share.getDiskFreeSpace();
            assertTrue(free > 0, "a writable share should report free space, reported " + free);
        }
    }

    @Test
    @DisplayName("a share root reports itself as a share")
    void shareRootReportsItselfAsAShare() throws Exception {
        final CIFSContext context = server().context();
        try (SmbFile share = new SmbFile(server().url(server().share()), context)) {
            assertEquals(SmbConstants.TYPE_SHARE, share.getType(), "a share root should report TYPE_SHARE");
        }
    }

    @Test
    @DisplayName("a file reports a non-zero index that survives a rename")
    void fileReportsAnIndexThatSurvivesARename() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "indexed.txt", "payload");

        final long before = file.fileIndex();
        assertNotEquals(0L, before, "a file on an SMB2 connection should report an index");

        final SmbFile renamed = new SmbFile(this.workDir, "indexed-renamed.txt");
        file.renameTo(renamed);
        assertEquals(before, renamed.fileIndex(), "renaming a file should not change the identity the server reports for it");
    }

    @Test
    @DisplayName("two different files report different indexes")
    void differentFilesReportDifferentIndexes() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile first = writeFile(this.workDir, "one.txt", "one");
        final SmbFile second = writeFile(this.workDir, "two.txt", "two");

        assertNotEquals(first.fileIndex(), second.fileIndex(), "distinct files should have distinct indexes");
    }
}
