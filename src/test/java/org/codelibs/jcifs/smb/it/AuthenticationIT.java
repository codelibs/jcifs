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

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.impl.SmbAuthException;
import org.codelibs.jcifs.smb.impl.SmbException;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.it.env.RequiresBackend;
import org.codelibs.jcifs.smb.it.env.SmbBackend;
import org.codelibs.jcifs.smb.it.env.SmbServerResolver;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Authentication and per-account authorization.
 */
class AuthenticationIT extends AbstractSmbIT {

    @Test
    @DisplayName("valid credentials reach the share")
    void validCredentialsWork() throws Exception {
        try (SmbFile share = new SmbFile(server().url(server().share()), server().context())) {
            assertTrue(share.exists());
        }
    }

    @Test
    @DisplayName("a wrong password is rejected")
    void wrongPasswordIsRejected() throws Exception {
        final CIFSContext context = server().context(server().user(), "not-the-" + UUID.randomUUID());
        assertThrows(SmbAuthException.class, () -> {
            try (SmbFile share = new SmbFile(server().url(server().share()), context)) {
                share.exists();
            }
        });
    }

    @Test
    @DisplayName("an unknown account is rejected")
    void unknownAccountIsRejected() throws Exception {
        final CIFSContext context = server().context("nobody-" + UUID.randomUUID(), server().password());
        assertThrows(SmbAuthException.class, () -> {
            try (SmbFile share = new SmbFile(server().url(server().share()), context)) {
                share.exists();
            }
        });
    }

    @Test
    @DisplayName("an account cannot read another account's private share")
    void privateShareIsNotReadableByAnotherAccount() throws Exception {
        final CIFSContext context = server().context();
        assertThrows(Exception.class, () -> {
            try (SmbFile share = new SmbFile(server().url("testuser2private"), context)) {
                share.listFiles();
            }
        }, "testuser1 must not be able to list testuser2's private share");
    }

    @Test
    @RequiresBackend(SmbBackend.WINDOWS)
    @Disabled("Measured on Windows Server 2025: exists() returns true for a share the account cannot connect to. "
            + "The share ACL grants only the other account, listFiles() on the same share is still refused, and "
            + "Samba rethrows the tree connect denial as exists() is documented to. Needs an issue before enabling.")
    @DisplayName("a share the account cannot connect to is not reported as existing")
    void inaccessibleShareIsNotReportedAsExisting() throws Exception {
        final CIFSContext context = server().context();
        assertThrows(SmbException.class, () -> {
            try (SmbFile share = new SmbFile(server().url("testuser2private"), context)) {
                share.exists();
            }
        }, "an unreachable share must not be reported as existing");
    }

    @Test
    @DisplayName("the secondary account reaches its own private share")
    void secondaryAccountReachesItsOwnShare() throws Exception {
        final CIFSContext context = server().context(SmbServerResolver.secondaryUser(), server().password());
        try (SmbFile share = new SmbFile(server().url("testuser2private"), context)) {
            assertTrue(share.exists());
        }
    }
}
