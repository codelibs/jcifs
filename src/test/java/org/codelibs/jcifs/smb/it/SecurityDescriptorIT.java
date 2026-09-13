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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

import org.codelibs.jcifs.smb.ACE;
import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.SID;
import org.codelibs.jcifs.smb.dcerpc.DcerpcError;
import org.codelibs.jcifs.smb.dcerpc.DcerpcException;
import org.codelibs.jcifs.smb.impl.SmbException;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.impl.WinError;
import org.codelibs.jcifs.smb.it.env.DialectMatrix;
import org.codelibs.jcifs.smb.it.env.RequiresBackend;
import org.codelibs.jcifs.smb.it.env.SmbBackend;
import org.codelibs.jcifs.smb.it.env.SmbServerResolver;
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
 *
 * <p>
 * A DACL is only the start of deciding who may read a file. A caller also has to
 * tell an allow entry from a deny and an account from a group, and a group has to
 * be expanded into its members over SAMR - a second named pipe, and the one part
 * of this path no other test reaches. Both backends carry a local group holding
 * both test accounts and a file granted to it for that.
 * </p>
 */
class SecurityDescriptorIT extends AbstractSmbIT {

    /** The local group both fixtures create, holding both test accounts. */
    private static final String GROUP = "jcifsgroup";

    /** The well-known SID of Everyone. */
    private static final String EVERYONE = "S-1-1-0";

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

    @Test
    @DisplayName("the owner of a file the account wrote resolves to that account")
    void ownerResolvesToTheAccountThatWroteTheFile() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "mine.txt", "payload");

        final SID owner = file.getOwnerUser();
        assertNotNull(owner, "a file should report an owner");
        assertEquals(SID.SID_TYPE_USER, owner.getType(),
                "the owner should resolve to an account, was " + owner.getTypeText() + ": " + owner);
        assertTrue(server().user().equalsIgnoreCase(owner.getAccountName()),
                "the owner should be the account that wrote the file, was: " + owner.toDisplayString());
        assertNotNull(owner.getDomainName(), "a resolved owner should name its domain: " + owner);
        assertFalse(owner.getDomainName().isEmpty(), "a resolved owner should name its domain: " + owner);
    }

    @Test
    @DisplayName("a file nothing is denied on reports only allow entries")
    void ordinaryFileReportsOnlyAllowEntries() throws Exception {
        try (SmbFile file = new SmbFile(server().url(server().share(), "access/readable.txt"), server().context())) {
            final ACE[] aces = file.getSecurity(false);
            assertTrue(aces.length > 0, "the DACL should carry at least one entry");
            assertTrue(Arrays.stream(aces).allMatch(ACE::isAllow), "no entry on this file denies anything: " + Arrays.toString(aces));
        }
    }

    @Test
    @RequiresBackend(SmbBackend.WINDOWS)
    @DisplayName("Windows reports an explicit deny as a deny entry naming the account")
    void windowsReportsAnExplicitDeny() throws Exception {
        // The fixture denies each test account FILE_READ_DATA on this file with icacls /deny (RD).
        try (SmbFile file = new SmbFile(server().url(server().share(), "access/noaccess.txt"), server().context())) {
            final ACE[] aces = file.getSecurity(true);
            assertTrue(
                    Arrays.stream(aces)
                            .anyMatch(ace -> !ace.isAllow() && server().user().equalsIgnoreCase(ace.getSID().getAccountName())
                                    && (ace.getAccessMask() & ACE.FILE_READ_DATA) != 0),
                    "no deny entry names " + server().user() + " and read access: " + Arrays.toString(aces));
        }
    }

    @Test
    @RequiresBackend(SmbBackend.SAMBA)
    @DisplayName("Samba withholds rights with an allow entry that grants nothing, never a deny")
    void sambaWithholdsRightsWithAnEmptyAllowEntry() throws Exception {
        // Samba builds the DACL from POSIX mode bits and emits no deny entries. A file
        // closed to everyone but its owner and its group (mode 0640) still lists
        // Everyone, as an allow entry with an empty mask. A caller that sorts entries by
        // isAllow() alone reads that as a grant; what is actually granted is only in the
        // mask.
        try (SmbFile file = new SmbFile(server().url(server().share(), "groups/group.txt"), server().context())) {
            final ACE[] aces = file.getSecurity(false);
            assertTrue(Arrays.stream(aces).allMatch(ACE::isAllow), "Samba should report no deny entry: " + Arrays.toString(aces));
            assertTrue(Arrays.stream(aces).anyMatch(ace -> EVERYONE.equals(ace.getSID().toString()) && ace.getAccessMask() == 0),
                    "Everyone should be listed as an allow entry granting nothing: " + Arrays.toString(aces));
        }
    }

    @Test
    @RequiresBackend(SmbBackend.SAMBA)
    @DisplayName("Samba lets an ordinary account expand a group named in a DACL into its members")
    void sambaLetsAnOrdinaryAccountExpandAGroup() throws Exception {
        final CIFSContext context = server().context();
        try (SmbFile file = new SmbFile(server().url(server().share(), "groups/group.txt"), context)) {
            final SID group = groupNamedInTheDaclOf(file);

            final SID[] members = memberSidsOf(context, file, group);
            final Set<String> names = Arrays.stream(members)
                    .map(sid -> String.valueOf(sid.getAccountName()).toLowerCase(Locale.ROOT))
                    .collect(Collectors.toSet());
            assertEquals(Set.of(server().user().toLowerCase(Locale.ROOT), SmbServerResolver.secondaryUser()), names,
                    "unexpected members of " + GROUP + ": " + Arrays.toString(members));
        }
    }

    @Test
    @RequiresBackend(SmbBackend.WINDOWS)
    @DisplayName("Windows refuses an ordinary account the members of a group named in a DACL")
    void windowsRefusesAnOrdinaryAccountTheMembersOfAGroup() throws Exception {
        // Naming the group still works: LSARPC resolves it, as an alias, for any
        // account. Listing its members does not. Windows refuses the SAMR connect
        // itself to an account that is not an administrator, which is the default of
        // its policy restricting remote calls to SAM. A caller expanding groups with an
        // ordinary account therefore gets the group and none of its members, and has
        // to be ready for the refusal. Samba answers the same call for anyone.
        final CIFSContext context = server().context();
        try (SmbFile file = new SmbFile(server().url(server().share(), "groups/group.txt"), context)) {
            final SID group = groupNamedInTheDaclOf(file);

            final CIFSException e = assertThrows(CIFSException.class, () -> memberSidsOf(context, file, group),
                    "a non-administrator should not be able to list the members of a group on Windows");
            final DcerpcException refusal =
                    assertInstanceOf(DcerpcException.class, e.getCause(), "the refusal should come from the RPC layer: " + e);
            assertEquals(DcerpcError.DCERPC_FAULT_ACCESS_DENIED, refusal.getErrorCode(), "unexpected refusal: " + refusal);
        }
    }

    /**
     * The fixture's local group, as the file's DACL names it once resolved.
     */
    private static SID groupNamedInTheDaclOf(final SmbFile file) throws Exception {
        final ACE[] aces = file.getSecurity(true);
        final SID group = Arrays.stream(aces)
                .map(ACE::getSID)
                .filter(sid -> GROUP.equalsIgnoreCase(sid.getAccountName()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("the DACL does not name " + GROUP + ": " + Arrays.toString(aces)));
        assertEquals(SID.SID_TYPE_ALIAS, group.getType(), "a local group should resolve as an alias, was " + group.getTypeText());
        return group;
    }

    /**
     * Asks the file's server for the members of a group, the way a caller expanding
     * a DACL does.
     */
    private static SID[] memberSidsOf(final CIFSContext context, final SmbFile file, final SID group) throws CIFSException {
        return context.getSIDResolver()
                .getGroupMemberSids(context, authority(file), group.getDomainSid(), group.getRid(),
                        org.codelibs.jcifs.smb.impl.SID.SID_FLAG_RESOLVE_SIDS);
    }

    /**
     * The authority a DCERPC call about a file goes to: its server, and the port
     * when the URL names one. It is how {@code SmbFile} itself addresses LSARPC to
     * resolve an owner; {@code getServer()} alone reaches the same server only when
     * it answers on the default port.
     */
    private static String authority(final SmbFile file) {
        final int port = file.getLocator().getPort();
        return port == -1 ? file.getServer() : file.getServer() + ":" + port;
    }
}
