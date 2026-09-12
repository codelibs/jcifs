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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.impl.SmbException;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * What opening a random access file does to a file that is not there.
 *
 * <p>
 * The flags a random access file opens with are replayed whenever its handle has to be reopened, so asking the server
 * to create the file is not a one-off: it applies again after every dropped connection. A unit test can show which
 * flags are sent; only a real server shows what they do.
 * </p>
 */
class RandomAccessOpenIT extends AbstractSmbIT {

    private SmbFile workDir;

    @AfterEach
    void removeWorkDir() {
        deleteQuietly(this.workDir);
    }

    @Test
    @DisplayName("opening a missing file read-only fails instead of creating it")
    void testReadOnlyOpenDoesNotCreate() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile missing = new SmbFile(this.workDir, "never-written.txt");

        assertFalse(missing.exists(), "the file must not exist for this test to mean anything");

        // The constructor opens the file straight away, so a refused open surfaces here.
        assertThrows(SmbException.class, () -> missing.openRandomAccess("r"), "opening a file that is not there read-only should fail");

        assertFalse(missing.exists(), "a read-only open must not bring the file into existence");
    }

    @Test
    @DisplayName("read-write mode still creates the file, as it always has")
    void testReadWriteOpenStillCreates() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile created = new SmbFile(this.workDir, "written-by-rw.txt");

        assertFalse(created.exists(), "the file must not exist beforehand");

        created.openRandomAccess("rw").close();

        // Dropping O_CREAT for read-only must not have taken it away from read-write, which callers rely on.
        assertTrue(created.exists(), "opening read-write should still create the file");
    }
}
