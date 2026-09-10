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

import java.util.UUID;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.impl.NtStatus;
import org.codelibs.jcifs.smb.impl.SmbException;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * How server errors surface as exceptions.
 */
class ErrorMappingIT extends AbstractSmbIT {

    @Test
    @DisplayName("a missing file reports OBJECT_NAME_NOT_FOUND when opened")
    void missingFileReportsNotFound() throws Exception {
        final CIFSContext context = server().context();
        try (SmbFile file = new SmbFile(server().url(server().share(), "missing-" + UUID.randomUUID() + ".txt"), context)) {
            assertFalse(file.exists());
            final SmbException e = assertThrows(SmbException.class, file::getInputStream);
            assertEquals(NtStatus.NT_STATUS_OBJECT_NAME_NOT_FOUND, e.getNtStatus(),
                    "unexpected status: 0x" + Integer.toHexString(e.getNtStatus()));
        }
    }

    @Test
    @DisplayName("a share the account cannot reach reports a failure")
    void inaccessibleShareFails() throws Exception {
        final CIFSContext context = server().context();
        assertThrows(SmbException.class, () -> {
            try (SmbFile file = new SmbFile(server().url("testuser2private", "denied.txt"), context)) {
                file.createNewFile();
            }
        }, "testuser1 must not be able to write into testuser2's private share");
    }

    @Test
    @DisplayName("a share that does not exist reports a failure")
    void missingShareFails() throws Exception {
        final CIFSContext context = server().context();
        assertThrows(SmbException.class, () -> {
            try (SmbFile file = new SmbFile(server().url("no-such-share-" + UUID.randomUUID()), context)) {
                file.listFiles();
            }
        });
    }
}
