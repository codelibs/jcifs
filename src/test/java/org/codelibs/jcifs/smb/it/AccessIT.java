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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.impl.SmbException;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * What a caller can find out about its own access to a file.
 *
 * <p>
 * The fixture puts three files in one directory of a share both accounts may
 * write: one ordinary, one the account may read but not write, and one it may
 * not read at all. The share grants the same rights to all three, so anything
 * that answers from the share alone answers the same for each of them - only
 * the access the server computes for the file itself tells them apart.
 * </p>
 *
 * <p>
 * These cases pin what has to stay true either way. A file that denies its
 * contents still reports that it exists, which is a different fact from being
 * readable, and an ordinary file in the same directory is unaffected. What
 * {@code canRead()} and {@code canWrite()} answer for the restricted two is
 * asserted where that behaviour is implemented, not here.
 * </p>
 */
class AccessIT extends AbstractSmbIT {

    private SmbFile access(final String name) throws Exception {
        return new SmbFile(server().url(server().share(), "access/" + name), server().context());
    }

    @Test
    @DisplayName("an ordinary file reports that it exists, can be read and can be written")
    void ordinaryFileIsUnrestricted() throws Exception {
        try (SmbFile file = access("readable.txt")) {
            assertTrue(file.exists(), "the fixture file should exist");
            assertTrue(file.canRead(), "an ordinary file should report that it can be read");
            assertTrue(file.canWrite(), "an ordinary file in a writable share should report that it can be written");
            assertEquals("readable contents\n", contentsOf(file));
        }
    }

    @Test
    @DisplayName("a file the account may not read still reports that it exists")
    void unreadableFileStillReportsThatItExists() throws Exception {
        try (SmbFile file = access("noaccess.txt")) {
            assertTrue(file.exists(), "a file whose contents are denied should still report that it exists");
        }
    }

    @Test
    @DisplayName("reading a file the account may not read is refused")
    void readingAnUnreadableFileIsRefused() throws Exception {
        try (SmbFile file = access("noaccess.txt")) {
            assertThrows(SmbException.class, () -> {
                try (InputStream in = file.getInputStream()) {
                    in.read();
                }
            }, "the server should refuse the contents of a file the account may not read");
        }
    }

    @Test
    @DisplayName("a file the account may not write can still be read")
    void readOnlyFileCanStillBeRead() throws Exception {
        try (SmbFile file = access("readonly.txt")) {
            assertTrue(file.exists(), "the fixture file should exist");
            assertTrue(file.canRead(), "a read-only file should report that it can be read");
            assertEquals("read-only contents\n", contentsOf(file));
        }
    }

    @Test
    @DisplayName("writing a file the account may not write is refused")
    void writingAReadOnlyFileIsRefused() throws Exception {
        try (SmbFile file = access("readonly.txt")) {
            assertThrows(SmbException.class, () -> {
                try (OutputStream out = file.getOutputStream()) {
                    out.write('x');
                }
            }, "the server should refuse a write to a file the account may only read");
        }
    }

    @Test
    @DisplayName("a file that is not there reports neither read nor write")
    void missingFileReportsNeither() throws Exception {
        try (SmbFile file = access("missing-" + UUID.randomUUID() + ".txt")) {
            assertFalse(file.exists(), "the file should not exist");
            assertFalse(file.canRead(), "a file that is not there cannot be read");
            assertFalse(file.canWrite(), "a file that is not there cannot be written");
        }
    }

    @Test
    @DisplayName("a directory reports that it can be read")
    void directoryIsReadable() throws Exception {
        final CIFSContext context = server().context();
        try (SmbFile dir = new SmbFile(server().url(server().share(), "access/"), context)) {
            assertTrue(dir.exists(), "the fixture directory should exist");
            assertTrue(dir.canRead(), "a directory the account may list should report that it can be read");
        }
    }

    private static String contentsOf(final SmbFile file) throws Exception {
        try (InputStream in = file.getInputStream()) {
            final ByteArrayOutputStream buf = new ByteArrayOutputStream();
            final byte[] chunk = new byte[512];
            int read;
            while ((read = in.read(chunk)) > 0) {
                buf.write(chunk, 0, read);
            }
            return buf.toString(StandardCharsets.UTF_8);
        }
    }
}
