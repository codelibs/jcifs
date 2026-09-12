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

import java.io.InputStream;
import java.io.OutputStream;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.impl.NtStatus;
import org.codelibs.jcifs.smb.impl.SmbException;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.it.env.DialectMatrix;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Share modes, and what a server does when a second open conflicts with them.
 *
 * <p>
 * Every other test in this suite opens files with the default sharing mode, so
 * nothing exercised the {@code sharing} arguments of
 * {@link SmbFile#openInputStream(int)} and its siblings, and nothing pinned what
 * a sharing violation looks like from the caller's side. The mode is carried in
 * the SMB2 CREATE request and enforced by the server, so these are contracts of
 * the pair, not of the client alone.
 * </p>
 */
class ShareModeIT extends AbstractSmbIT {

    private SmbFile workDir;

    @AfterEach
    void removeWorkDir() {
        deleteQuietly(this.workDir);
    }

    @DialectMatrix
    @DisplayName("a second open is refused while the first denies sharing")
    void secondOpenIsRefusedWhileTheFirstDeniesSharing(final DialectVersion dialect) throws Exception {
        final CIFSContext context = contextFor(dialect);
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "exclusive.txt", "payload");

        try (InputStream held = file.openInputStream(SmbConstants.FILE_NO_SHARE)) {
            final SmbException e = assertThrows(SmbException.class, () -> file.openInputStream(SmbConstants.FILE_NO_SHARE).close(),
                    "a second open should have been refused while the first denied sharing");
            assertEquals(NtStatus.NT_STATUS_SHARING_VIOLATION, e.getNtStatus(),
                    "unexpected status: 0x" + Integer.toHexString(e.getNtStatus()));
        }
    }

    @DialectMatrix
    @DisplayName("a second open succeeds while the first grants sharing")
    void secondOpenSucceedsWhileTheFirstGrantsSharing(final DialectVersion dialect) throws Exception {
        final CIFSContext context = contextFor(dialect);
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "shared.txt", "payload");

        try (InputStream held = file.openInputStream(SmbConstants.DEFAULT_SHARING);
                InputStream second = file.openInputStream(SmbConstants.DEFAULT_SHARING)) {
            assertEquals('p', second.read(), "the second reader should see the file contents");
        }
    }

    @Test
    @DisplayName("deleting a file held without FILE_SHARE_DELETE is refused")
    void deleteIsRefusedWhileTheFileIsHeldWithoutShareDelete() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "held.txt", "payload");

        try (InputStream held = file.openInputStream(SmbConstants.FILE_NO_SHARE)) {
            final SmbException e = assertThrows(SmbException.class, file::delete,
                    "delete should have been refused while the file was held without FILE_SHARE_DELETE");
            assertEquals(NtStatus.NT_STATUS_SHARING_VIOLATION, e.getNtStatus(),
                    "unexpected status: 0x" + Integer.toHexString(e.getNtStatus()));
        }
        assertTrue(file.exists(), "the refused delete should have left the file in place");
    }

    @Test
    @DisplayName("deleting a file held with FILE_SHARE_DELETE succeeds")
    void deleteSucceedsWhileTheFileIsHeldWithShareDelete() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "deletable.txt", "payload");

        try (InputStream held = file.openInputStream(SmbConstants.DEFAULT_SHARING)) {
            file.delete();
        }
        assertFalse(file.exists(), "the file should be gone once the handle that allowed the delete is closed");
    }

    @Test
    @DisplayName("renaming a file held without sharing is refused")
    void renameIsRefusedWhileTheFileIsHeldWithoutSharing() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "renameheld.txt", "payload");
        final SmbFile target = new SmbFile(this.workDir, "renamed.txt");

        try (InputStream held = file.openInputStream(SmbConstants.FILE_NO_SHARE)) {
            final SmbException e = assertThrows(SmbException.class, () -> file.renameTo(target),
                    "rename should have been refused while the file was held without sharing");
            assertEquals(NtStatus.NT_STATUS_SHARING_VIOLATION, e.getNtStatus(),
                    "unexpected status: 0x" + Integer.toHexString(e.getNtStatus()));
        }
        assertFalse(target.exists(), "the refused rename should not have created the target");
    }

    @Test
    @DisplayName("a writer that denies sharing locks out a reader")
    void writerThatDeniesSharingLocksOutAReader() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "writerheld.txt", "payload");

        try (OutputStream held = file.openOutputStream(false, SmbConstants.FILE_NO_SHARE)) {
            final SmbException e = assertThrows(SmbException.class, () -> file.openInputStream(SmbConstants.DEFAULT_SHARING).close(),
                    "a reader should have been refused while a writer denied sharing");
            assertEquals(NtStatus.NT_STATUS_SHARING_VIOLATION, e.getNtStatus(),
                    "unexpected status: 0x" + Integer.toHexString(e.getNtStatus()));
        }
    }
}
