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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.codelibs.jcifs.smb.ACE;
import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.SID;
import org.codelibs.jcifs.smb.impl.SmbException;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.impl.WinError;
import org.codelibs.jcifs.smb.it.env.DialectMatrix;
import org.codelibs.jcifs.smb.it.env.RequiresBackend;
import org.codelibs.jcifs.smb.it.env.SmbBackend;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Security descriptors read back from a real server.
 *
 * <p>
 * {@code getSecurity}, {@code getOwnerUser} and {@code getOwnerGroup} go out as
 * an SMB2 QUERY_INFO carrying SECURITY_INFORMATION, and resolving the SIDs in
 * the result goes further still - out to LSARPC over the {@code IPC$} named
 * pipe. Until this class existed no integration test reached either path, so the
 * whole DCERPC half of the client was covered only by unit tests with no server
 * on the other end.
 * </p>
 *
 * <p>
 * The two backends disagree about the content and that is deliberate: Samba
 * synthesises a descriptor from POSIX mode bits while Windows returns real NTFS
 * ACEs. The assertions therefore pin the shape - a descriptor comes back, it has
 * at least one entry, the owner is a SID, a resolved entry carries a name - and
 * not the particular rights either server chooses to report.
 * </p>
 */
class SecurityDescriptorIT extends AbstractSmbIT {

    private SmbFile workDir;

    @AfterEach
    void removeWorkDir() {
        deleteQuietly(this.workDir);
    }

    @DialectMatrix
    @DisplayName("a file has a readable DACL")
    void fileHasAReadableDacl(final DialectVersion dialect) throws Exception {
        final CIFSContext context = contextFor(dialect);
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "acl.txt", "payload");

        final ACE[] aces = file.getSecurity(false);
        assertNotNull(aces, "a file the caller can read should have a readable DACL");
        assertTrue(aces.length > 0, "the DACL should carry at least one entry");
        assertTrue(Arrays.stream(aces).allMatch(ace -> ace.getSID() != null), "every entry should name a SID: " + Arrays.toString(aces));
    }

    @Test
    @DisplayName("resolving a DACL turns at least one SID into an account name")
    void resolvingADaclNamesAnAccount() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "resolved.txt", "payload");

        final ACE[] aces = file.getSecurity(true);
        assertNotNull(aces, "a file the caller can read should have a readable DACL");
        assertTrue(aces.length > 0, "the DACL should carry at least one entry");
        assertTrue(
                Arrays.stream(aces)
                        .anyMatch(ace -> ace.getSID() != null && ace.getSID().getAccountName() != null
                                && !ace.getSID().getAccountName().isEmpty()),
                "no entry resolved to an account name: " + Arrays.toString(aces));
    }

    @Test
    @DisplayName("the owner and the group come back as SIDs")
    void ownerAndGroupComeBackAsSids() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "owner.txt", "payload");

        final SID owner = file.getOwnerUser();
        assertNotNull(owner, "a file should report an owner");
        assertTrue(owner.toString().startsWith("S-1-"), "the owner should be a SID, was: " + owner);

        final SID group = file.getOwnerGroup();
        assertNotNull(group, "a file should report an owning group");
        assertTrue(group.toString().startsWith("S-1-"), "the group should be a SID, was: " + group);
    }

    @Test
    @RequiresBackend(SmbBackend.SAMBA)
    @DisplayName("Samba lets an ordinary account read a share's security descriptor")
    void sambaLetsAnOrdinaryAccountReadTheShareDescriptor() throws Exception {
        final CIFSContext context = server().context();
        try (SmbFile share = new SmbFile(server().url(server().share()), context)) {
            final ACE[] aces = share.getShareSecurity(false);
            assertNotNull(aces, "Samba should return the descriptor to any account that can reach the share");
            assertTrue(aces.length > 0, "the share descriptor should carry at least one entry");
        }
    }

    @Test
    @RequiresBackend(SmbBackend.WINDOWS)
    @DisplayName("Windows refuses an ordinary account the share's security descriptor")
    void windowsRefusesAnOrdinaryAccountTheShareDescriptor() throws Exception {
        // getShareSecurity is srvsvc NetShareGetInfo at level 502, and Windows only
        // answers that for an administrator. Samba answers it for anyone who can
        // reach the share. Both are faithful; the call is simply not portable, and
        // callers have to be ready for the refusal.
        //
        // The code is the Win32 ERROR_ACCESS_DENIED rather than the NT status
        // STATUS_ACCESS_DENIED the file-level calls report: getShareSecurity wraps
        // the RPC return value directly, as new SmbException(rpc.retval, true). A
        // caller matching on the NT status alone will not recognise this one.
        final CIFSContext context = server().context();
        try (SmbFile share = new SmbFile(server().url(server().share()), context)) {
            final SmbException e = assertThrows(SmbException.class, () -> share.getShareSecurity(false),
                    "a non-administrator should not be able to read the share descriptor on Windows");
            assertEquals(WinError.ERROR_ACCESS_DENIED, e.getNtStatus(), "unexpected status: 0x" + Integer.toHexString(e.getNtStatus()));
        }
    }
}
