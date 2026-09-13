package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.codelibs.jcifs.smb1.dcerpc.DcerpcHandle;
import org.codelibs.jcifs.smb1.dcerpc.DcerpcMessage;
import org.codelibs.jcifs.smb1.dcerpc.msrpc.MsrpcGetMembersInAlias;
import org.codelibs.jcifs.smb1.dcerpc.msrpc.SamrDomainHandle;
import org.codelibs.jcifs.smb1.dcerpc.msrpc.lsarpc;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The SIDs a crawler takes out of a security descriptor and turns into search roles.
 *
 * <p>
 * A crawler reads each ACE's SID, asks for its type to decide whether it is a group, expands a group into its members
 * and keys a set on the result. Everything here that would otherwise reach a server answers from the fields a resolved
 * SID already carries, from the process-wide SID cache, or from a mocked DCERPC handle.
 * </p>
 */
class SIDTest {

    /** A domain SID whose second and third sub-authorities do not fit in a signed int, as real domain SIDs often do. */
    private static final String DOMAIN = "S-1-5-21-1496946806-2192648263-3843101252";

    /** A host that cannot be reached, for calls that must answer before they would connect anywhere. */
    private static final String UNREACHABLE = "unreachable.invalid";

    private final List<SID> cached = new ArrayList<>();

    private NtlmPasswordAuthentication auth;

    @BeforeEach
    void setUp() {
        this.auth = new NtlmPasswordAuthentication("WNET", "crawler", "secret");
    }

    @AfterEach
    void clearCache() {
        synchronized (SID.sid_cache) {
            this.cached.forEach(SID.sid_cache::remove);
        }
    }

    @SuppressWarnings("unchecked")
    private void cache(final SID... sids) {
        synchronized (SID.sid_cache) {
            for (final SID sid : sids) {
                SID.sid_cache.put(sid, sid);
                this.cached.add(sid);
            }
        }
    }

    private static SID resolved(final String textual, final int type, final String domain, final String account) throws SmbException {
        return new SID(new SID(textual), type, domain, account, false);
    }

    /** An NT-authority SID in the self-relative binary form, starting {@code offset} bytes into the buffer. */
    private static byte[] wireSid(final int offset, final long... subAuthorities) {
        final ByteBuffer buffer = ByteBuffer.allocate(offset + 8 + 4 * subAuthorities.length).order(ByteOrder.LITTLE_ENDIAN);
        buffer.position(offset);
        buffer.put((byte) 1).put((byte) subAuthorities.length).put(new byte[] { 0, 0, 0, 0, 0, 5 });
        for (final long subAuthority : subAuthorities) {
            buffer.putInt((int) subAuthority);
        }
        return buffer.array();
    }

    /** A SAMR pipe that answers the alias member request with the given status and members. */
    private DcerpcHandle samrHandle(final int membersStatus, final SID... members) throws Exception {
        final DcerpcHandle handle = mock(DcerpcHandle.class);
        when(handle.getServer()).thenReturn("fileserver");
        when(handle.getPrincipal()).thenReturn(this.auth);
        doAnswer(invocation -> {
            if (invocation.getArgument(0) instanceof final MsrpcGetMembersInAlias rpc) {
                rpc.retval = membersStatus;
                rpc.sids.num_sids = members.length;
                rpc.sids.sids = new lsarpc.LsarSidPtr[members.length];
                for (int i = 0; i < members.length; i++) {
                    rpc.sids.sids[i] = new lsarpc.LsarSidPtr();
                    rpc.sids.sids[i].sid = members[i];
                }
            }
            return null;
        }).when(handle).sendrecv(any(DcerpcMessage.class));
        return handle;
    }

    @Test
    @DisplayName("a textual SID prints back unchanged, unsigned sub-authorities included")
    void textualSidRoundTrips() throws Exception {
        final SID sid = new SID(DOMAIN + "-1029");

        assertEquals(DOMAIN + "-1029", sid.toString());
        assertEquals(1029, sid.getRid());
    }

    @Test
    @DisplayName("the binary form a security descriptor carries decodes to the same SID")
    void binarySidEqualsTextualSid() throws Exception {
        final byte[] wire = wireSid(3, 21, 1496946806L, 2192648263L, 3843101252L, 1029);

        final SID binary = new SID(wire, 3);

        assertEquals(DOMAIN + "-1029", binary.toString());
        assertEquals(new SID(DOMAIN + "-1029"), binary);
        assertEquals(new SID(DOMAIN + "-1029").hashCode(), binary.hashCode());
    }

    @Test
    @DisplayName("a malformed textual SID is refused")
    void malformedTextualSidIsRefused() {
        assertThrows(SmbException.class, () -> new SID("S-1"));
        assertThrows(SmbException.class, () -> new SID("X-1-5-21"));
    }

    @Test
    @DisplayName("a binary SID claiming more than 100 sub-authorities is refused")
    void oversizedBinarySidIsRefused() {
        final byte[] wire = { 1, 101, 0, 0, 0, 0, 0, 5 };

        assertThrows(RuntimeException.class, () -> new SID(wire, 0));
    }

    @Test
    @DisplayName("a domain SID and a RID compose the account SID")
    void domainSidAndRidCompose() throws Exception {
        assertEquals(DOMAIN + "-1105", new SID(new SID(DOMAIN), 1105).toString());
    }

    @Test
    @DisplayName("a resolved user carries its name, domain and type")
    void resolvedUserCarriesItsNames() throws Exception {
        final SID alice = resolved(DOMAIN + "-1029", SID.SID_TYPE_USER, "WNET", "alice");

        assertEquals(SID.SID_TYPE_USER, alice.getType());
        assertEquals("User", alice.getTypeText());
        assertEquals("alice", alice.getAccountName());
        assertEquals("WNET", alice.getDomainName());
        assertEquals("WNET\\alice", alice.toDisplayString());
    }

    @Test
    @DisplayName("the domain SID of a resolved account is the account SID without its RID")
    void domainSidOfAnAccount() throws Exception {
        final SID domain = resolved(DOMAIN + "-1029", SID.SID_TYPE_USER, "WNET", "alice").getDomainSid();

        assertEquals(DOMAIN, domain.toString());
        assertEquals(SID.SID_TYPE_DOMAIN, domain.getType());
        assertEquals("WNET", domain.getDomainName());
        assertEquals("", domain.getAccountName());
        assertEquals("WNET", domain.toDisplayString());
        assertThrows(IllegalArgumentException.class, domain::getRid);
    }

    @Test
    @DisplayName("a domain group displays with its domain")
    void domainGroupDisplaysWithItsDomain() throws Exception {
        final SID group = resolved(DOMAIN + "-513", SID.SID_TYPE_DOM_GRP, "WNET", "Domain Users");

        assertEquals("Domain group", group.getTypeText());
        assertEquals("WNET\\Domain Users", group.toDisplayString());
        assertEquals(513, group.getRid());
    }

    @Test
    @DisplayName("a BUILTIN local group and a well-known group display by name alone")
    void builtinAndWellKnownGroupsDisplayByName() throws Exception {
        final SID administrators = resolved("S-1-5-32-544", SID.SID_TYPE_ALIAS, "BUILTIN", "Administrators");
        assertEquals("Local group", administrators.getTypeText());
        assertEquals("Administrators", administrators.toDisplayString());
        assertEquals("S-1-5-32", administrators.getDomainSid().toString());
        assertEquals(544, administrators.getRid());

        final SID everyone = resolved("S-1-1-0", SID.SID_TYPE_WKN_GRP, "", "Everyone");
        assertEquals("Builtin group", everyone.getTypeText());
        assertEquals("Everyone", everyone.toDisplayString());
    }

    @Test
    @DisplayName("a SID the server could not name falls back to its numbers")
    void unknownSidFallsBackToItsNumbers() throws Exception {
        final SID unknown = resolved(DOMAIN + "-4242", SID.SID_TYPE_UNKNOWN, null, null);

        assertEquals("4242", unknown.getAccountName());
        assertEquals(DOMAIN, unknown.getDomainName());
        assertEquals(DOMAIN + "-4242", unknown.toDisplayString());
    }

    @Test
    @DisplayName("a SID that was never resolved has no names and displays as its numbers")
    void unresolvedSidHasNoNames() throws Exception {
        final SID sid = new SID(DOMAIN + "-1029");

        assertEquals(SID.SID_TYPE_USE_NONE, sid.getType());
        assertNull(sid.getAccountName());
        assertNull(sid.getDomainName());
        assertEquals(DOMAIN + "-1029", sid.toDisplayString());
    }

    @Test
    @DisplayName("equality and hashing ignore resolution, so a set holds each SID once")
    void equalityIgnoresResolution() throws Exception {
        final Set<SID> set = new HashSet<>();
        set.add(new SID(DOMAIN + "-1029"));
        set.add(resolved(DOMAIN + "-1029", SID.SID_TYPE_USER, "WNET", "alice"));
        set.add(new SID(new SID(DOMAIN), 1029));

        assertEquals(1, set.size(), "the same SID was held more than once: " + set);
        assertNotEquals(new SID(DOMAIN + "-1029"), new SID(DOMAIN + "-1030"));
        assertNotEquals(new SID(DOMAIN), new SID(DOMAIN + "-1029"));
    }

    @Test
    @DisplayName("the well-known SIDs are the ones Windows uses")
    void wellKnownSids() {
        assertEquals("S-1-1-0", SID.EVERYONE.toString());
        assertEquals("S-1-3-0", SID.CREATOR_OWNER.toString());
        assertEquals("S-1-5-18", SID.SYSTEM.toString());
    }

    @Test
    @DisplayName("only a domain group or a local group has members; anything else answers none without connecting")
    void onlyGroupsHaveMembers() throws Exception {
        assertEquals(0, resolved(DOMAIN + "-1029", SID.SID_TYPE_USER, "WNET", "alice").getGroupMemberSids(UNREACHABLE, this.auth,
                SID.SID_FLAG_RESOLVE_SIDS).length);
        assertEquals(0, resolved("S-1-1-0", SID.SID_TYPE_WKN_GRP, "", "Everyone").getGroupMemberSids(UNREACHABLE, this.auth,
                SID.SID_FLAG_RESOLVE_SIDS).length);
        assertEquals(0, new SID(DOMAIN + "-513").getGroupMemberSids(UNREACHABLE, this.auth, SID.SID_FLAG_RESOLVE_SIDS).length,
                "an unresolved SID has no type, so it is never treated as a group");
    }

    @Test
    @DisplayName("the members of a group come back as SIDs tied to the server that listed them")
    void groupMembersComeBackAsSids() throws Exception {
        final DcerpcHandle handle = samrHandle(0, new SID(DOMAIN + "-1029"), new SID(DOMAIN + "-1105"));

        final SID[] members = SID.getGroupMemberSids0(handle, mock(SamrDomainHandle.class), new SID("S-1-5-32"), 544, 0);

        assertEquals(2, members.length);
        assertEquals(new SID(DOMAIN + "-1029"), members[0]);
        assertEquals(new SID(DOMAIN + "-1105"), members[1]);
        for (final SID member : members) {
            assertEquals("fileserver", member.origin_server, "a member has to remember where its name can be resolved");
            assertSame(this.auth, member.origin_auth);
        }
        // open the alias, read its members, close it
        verify(handle, times(3)).sendrecv(any(DcerpcMessage.class));
    }

    @Test
    @DisplayName("members asked for with resolution carry their types, so a nested group can be expanded in turn")
    void resolvedMembersCarryTheirTypes() throws Exception {
        cache(resolved(DOMAIN + "-1029", SID.SID_TYPE_USER, "WNET", "alice"),
                resolved(DOMAIN + "-1105", SID.SID_TYPE_DOM_GRP, "WNET", "Sales"));
        final DcerpcHandle handle = samrHandle(0, new SID(DOMAIN + "-1029"), new SID(DOMAIN + "-1105"));

        final SID[] members =
                SID.getGroupMemberSids0(handle, mock(SamrDomainHandle.class), new SID("S-1-5-32"), 544, SID.SID_FLAG_RESOLVE_SIDS);

        assertEquals(SID.SID_TYPE_USER, members[0].getType());
        assertEquals("alice", members[0].getAccountName());
        assertEquals(SID.SID_TYPE_DOM_GRP, members[1].getType());
        assertEquals("WNET\\Sales", members[1].toDisplayString());
    }

    @Test
    @DisplayName("a server that refuses to list a group's members fails the call and still closes the group")
    void refusedMemberListFails() throws Exception {
        final DcerpcHandle handle = samrHandle(NtStatus.NT_STATUS_ACCESS_DENIED);

        final SmbException e = assertThrows(SmbException.class,
                () -> SID.getGroupMemberSids0(handle, mock(SamrDomainHandle.class), new SID("S-1-5-32"), 544, 0));

        assertEquals(NtStatus.NT_STATUS_ACCESS_DENIED, e.getNtStatus());
        verify(handle, times(3)).sendrecv(any(DcerpcMessage.class));
    }

    @Test
    @DisplayName("resolving a slice of a batch of SIDs names only that slice")
    void resolvingASliceNamesOnlyThatSlice() throws Exception {
        cache(resolved(DOMAIN + "-1029", SID.SID_TYPE_USER, "WNET", "alice"),
                resolved(DOMAIN + "-1105", SID.SID_TYPE_DOM_GRP, "WNET", "Sales"));
        final SID[] batch = { new SID(DOMAIN + "-500"), new SID(DOMAIN + "-1029"), new SID(DOMAIN + "-1105") };

        SID.resolveSids(UNREACHABLE, this.auth, batch, 1, 2);

        assertNull(batch[0].getAccountName(), "the SID outside the slice must be left alone");
        assertEquals("alice", batch[1].getAccountName());
        assertEquals(SID.SID_TYPE_DOM_GRP, batch[2].getType());
        assertEquals("WNET\\Sales", batch[2].toDisplayString());
    }
}
