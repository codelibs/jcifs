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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.impl.NtStatus;
import org.codelibs.jcifs.smb.impl.SmbException;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.it.env.DialectMatrix;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Write modes: appending, replacing on rename, and the read-only attribute.
 *
 * <p>
 * All three change what the client puts on the wire. Appending skips the
 * truncate that {@code SmbFileOutputStream} otherwise performs with
 * FileEndOfFileInformation; replacing sets the flag in FileRenameInformation2;
 * and {@code SmbFile.delete()} clears the read-only attribute before it asks for
 * the delete, which makes it behave unlike {@code java.io.File}. None of the
 * three was covered.
 * </p>
 */
class WriteModeIT extends AbstractSmbIT {

    private SmbFile workDir;

    @AfterEach
    void removeWorkDir() {
        deleteQuietly(this.workDir);
    }

    @DialectMatrix
    @DisplayName("an appending stream adds to the file instead of truncating it")
    void appendingStreamAddsToTheFile(final DialectVersion dialect) throws Exception {
        final CIFSContext context = contextFor(dialect);
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "append.txt", "first");

        try (OutputStream out = file.openOutputStream(true)) {
            out.write("second".getBytes(StandardCharsets.UTF_8));
        }

        try (InputStream in = file.getInputStream()) {
            assertArrayEquals("firstsecond".getBytes(StandardCharsets.UTF_8), in.readAllBytes(),
                    "the appended bytes should follow the original ones");
        }
    }

    @Test
    @DisplayName("a non-appending stream truncates what was there")
    void nonAppendingStreamTruncates() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "truncate.txt", "a long original payload");

        try (OutputStream out = file.openOutputStream(false)) {
            out.write("short".getBytes(StandardCharsets.UTF_8));
        }

        assertEquals(5L, file.length(), "the shorter write should have truncated the file");
    }

    @Test
    @DisplayName("renaming onto an existing file is refused without the replace flag")
    void renameOntoExistingIsRefusedWithoutReplace() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile source = writeFile(this.workDir, "rename-src.txt", "source");
        writeFile(this.workDir, "rename-dst.txt", "destination");
        final SmbFile target = new SmbFile(this.workDir, "rename-dst.txt");

        final SmbException e = assertThrows(SmbException.class, () -> source.renameTo(target),
                "renaming onto an existing file should be refused without the replace flag");
        assertEquals(NtStatus.NT_STATUS_OBJECT_NAME_COLLISION, e.getNtStatus(),
                "unexpected status: 0x" + Integer.toHexString(e.getNtStatus()));
        assertTrue(source.exists(), "the refused rename should have left the source alone");
    }

    @Test
    @DisplayName("renaming onto an existing file replaces it when asked")
    void renameOntoExistingReplacesWhenAsked() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile source = writeFile(this.workDir, "replace-src.txt", "source");
        writeFile(this.workDir, "replace-dst.txt", "destination");
        final SmbFile target = new SmbFile(this.workDir, "replace-dst.txt");

        source.renameTo(target, true);

        assertFalse(source.exists(), "the source should be gone after the rename");
        try (InputStream in = target.getInputStream()) {
            assertArrayEquals("source".getBytes(StandardCharsets.UTF_8), in.readAllBytes(),
                    "the target should now hold what the source held");
        }
    }

    @Test
    @DisplayName("writing to a read-only file is refused")
    void writingToAReadOnlyFileIsRefused() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "readonly.txt", "payload");
        file.setReadOnly();

        final SmbException e =
                assertThrows(SmbException.class, () -> file.openOutputStream().close(), "a read-only file should not be writable");
        assertEquals(NtStatus.NT_STATUS_ACCESS_DENIED, e.getNtStatus(), "unexpected status: 0x" + Integer.toHexString(e.getNtStatus()));

        file.setReadWrite();
    }

    @Test
    @DisplayName("deleting a read-only file succeeds because the client clears the attribute first")
    void deletingAReadOnlyFileSucceeds() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "readonly-delete.txt", "payload");
        file.setReadOnly();

        file.delete();

        assertFalse(file.exists(), "SmbFile.delete clears the read-only attribute before deleting, so this should have succeeded");
    }
}
