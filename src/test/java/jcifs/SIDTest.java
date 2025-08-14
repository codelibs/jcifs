package jcifs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import jcifs.dcerpc.rpc;
import jcifs.smb.SID;
import jcifs.smb.SmbException;

/**
 * Tests for the SID class.
 */
class SIDTest {

    // A well-known SID for "Administrators"
    private final String adminSidString = "S-1-5-32-544";
    private final byte[] adminSidBytes = new byte[] { 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0 };

    /**
     * Test constructor with a valid SID string.
     *
     * @throws SmbException if the SID string is invalid
     */
    @Test
    void testStringConstructor() throws SmbException {
        SID sid = new SID(adminSidString);
        assertEquals(1, sid.revision);
        assertEquals(2, sid.sub_authority_count);
        assertEquals(5, sid.identifier_authority[5]);
        assertEquals(32, sid.sub_authority[0]);
        assertEquals(544, sid.sub_authority[1]);
        assertEquals(adminSidString, sid.toString());
    }

    /**
     * Test constructor with a SID string containing a hex value.
     *
     * @throws SmbException if the SID string is invalid
     */
    @Test
    void testStringConstructorWithHex() throws SmbException {
        SID sid = new SID("S-1-0x12-21-1");
        assertEquals(1, sid.revision);
        assertEquals(0x12, sid.identifier_authority[5]);
        assertEquals(2, sid.sub_authority_count);
        assertEquals(21, sid.sub_authority[0]);
        assertEquals(1, sid.sub_authority[1]);
    }

    /**
     * Test constructor with an invalid SID string.
     */
    @Test
    void testStringConstructorInvalidFormat() {
        assertThrows(SmbException.class, () -> new SID("invalid-sid"));
        assertThrows(SmbException.class, () -> new SID("S-1"));
    }

    /**
     * Test constructor with a byte array.
     */
    @Test
    void testByteArrayConstructor() {
        SID sid = new SID(adminSidBytes, 0);
        assertEquals(1, sid.revision);
        assertEquals(2, sid.sub_authority_count);
        assertEquals(5, sid.identifier_authority[5]);
        assertEquals(32, sid.sub_authority[0]);
        assertEquals(544, sid.sub_authority[1]);
        assertEquals(adminSidString, sid.toString());
    }

    /**
     * Test byte array constructor with too many sub-authorities.
     */
    @Test
    void testByteArrayConstructorTooManySubAuthorities() {
        byte[] badSid = new byte[10];
        badSid[1] = 101; // sub_authority_count > 100
        assertThrows(RuntimeCIFSException.class, () -> new SID(badSid, 0));
    }

    /**
     * Test constructor that combines a domain SID and an RID.
     *
     * @throws SmbException if the SID string is invalid
     */
    @Test
    void testDomainSidAndRidConstructor() throws SmbException {
        SID domainSid = new SID("S-1-5-21-123-456-789");
        int rid = 1000;
        SID userSid = new SID(domainSid, rid);
        assertEquals("S-1-5-21-123-456-789-1000", userSid.toString());
    }

    /**
     * Test constructor that combines a domain SID and a relative SID.
     *
     * @throws SmbException if the SID string is invalid
     */
    @Test
    void testDomainSidAndRelativeSidConstructor() throws SmbException {
        SID domainSid = new SID("S-1-5-21-123-456-789");
        SID relativeSid = new SID("S-1-5-1000"); // This is not a valid relative SID, but tests the logic
        relativeSid.sub_authority_count = 1;
        relativeSid.sub_authority = new int[] { 1000 };

        SID userSid = new SID(domainSid, relativeSid);
        assertEquals(domainSid.sub_authority_count + relativeSid.sub_authority_count, userSid.sub_authority_count);
        assertEquals(1000, userSid.sub_authority[userSid.sub_authority_count - 1]);
    }

    /**
     * Test the internal constructor.
     */
    @Test
    void testInternalConstructor() {
        rpc.sid_t rpcSid = new rpc.sid_t();
        rpcSid.revision = 1;
        rpcSid.sub_authority_count = 2;
        rpcSid.identifier_authority = new byte[] { 0, 0, 0, 0, 0, 5 };
        rpcSid.sub_authority = new int[] { 32, 544 };

        SID sid = new SID(rpcSid, SID.SID_TYPE_WKN_GRP, "BUILTIN", "Administrators", false);
        assertEquals(SID.SID_TYPE_WKN_GRP, sid.getType());
        assertEquals("BUILTIN", sid.getDomainName());
        assertEquals("Administrators", sid.getAccountName());
        assertEquals(adminSidString, sid.toString());
    }

    /**
     * Test converting a SID to a byte array.
     */
    @Test
    void testToByteArray() {
        SID sid = new SID(adminSidBytes, 0);
        assertArrayEquals(adminSidBytes, sid.toByteArray());
    }

    /**
     * Test the equals method.
     *
     * @throws SmbException if the SID string is invalid
     */
    @Test
    void testEquals() throws SmbException {
        SID sid1 = new SID(adminSidString);
        SID sid2 = new SID(adminSidBytes, 0);
        SID sid3 = new SID("S-1-1-0"); // Everyone

        assertEquals(sid1, sid1);
        assertEquals(sid1, sid2);
        assertNotEquals(sid1, sid3);
        assertNotEquals(sid1, null);
        assertNotEquals(sid1, new Object());
    }

    /**
     * Test the hashCode method.
     *
     * @throws SmbException if the SID string is invalid
     */
    @Test
    void testHashCode() throws SmbException {
        SID sid1 = new SID(adminSidString);
        SID sid2 = new SID(adminSidBytes, 0);
        SID sid3 = new SID("S-1-1-0");

        assertEquals(sid1.hashCode(), sid2.hashCode());
        assertNotEquals(sid1.hashCode(), sid3.hashCode());
    }

    /**
     * Test the toDisplayString method for a resolved SID.
     */
    @Test
    void testToDisplayStringResolved() {
        rpc.sid_t rpcSid = new rpc.sid_t();
        rpcSid.revision = 1;
        rpcSid.sub_authority_count = 2;
        rpcSid.identifier_authority = new byte[] { 0, 0, 0, 0, 0, 5 };
        rpcSid.sub_authority = new int[] { 32, 544 };

        SID sid = new SID(rpcSid, SID.SID_TYPE_ALIAS, "MYDOMAIN", "MyAlias", false);
        assertEquals("MYDOMAIN\\MyAlias", sid.toDisplayString());

        SID domainSid = new SID(rpcSid, SID.SID_TYPE_DOMAIN, "MYDOMAIN", null, true);
        assertEquals("MYDOMAIN", domainSid.toDisplayString());

        SID builtinSid = new SID(rpcSid, SID.SID_TYPE_WKN_GRP, "BUILTIN", "Administrators", false);
        assertEquals("Administrators", builtinSid.toDisplayString());
    }

    /**
     * Test the toDisplayString method for an unresolved SID.
     *
     * @throws SmbException if the SID string is invalid
     */
    @Test
    void testToDisplayStringUnresolved() throws SmbException {
        SID sid = new SID(adminSidString);
        assertEquals(adminSidString, sid.toDisplayString());
    }

    /**
     * Test getting the domain SID.
     *
     * @throws SmbException if the SID string is invalid
     */
    @Test
    void testGetDomainSid() throws SmbException {
        // Create a mock RPC SID to simulate a user SID
        rpc.sid_t rpcSid = new rpc.sid_t();
        rpcSid.revision = 1;
        rpcSid.sub_authority_count = 5; // Fixed: should be 5 for domain SID with RID
        rpcSid.identifier_authority = new byte[] { 0, 0, 0, 0, 0, 5 };
        rpcSid.sub_authority = new int[] { 21, 123, 456, 789, 1000 };

        SID userSid = new SID(rpcSid, SID.SID_TYPE_USER, "MYDOMAIN", "user", false);
        SID domainSid = userSid.getDomainSid();
        assertEquals("S-1-5-21-123-456-789", domainSid.toString());
        assertEquals(SID.SID_TYPE_DOMAIN, domainSid.getType());
    }

    /**
     * Test getting the RID.
     *
     * @throws SmbException if the SID string is invalid
     */
    @Test
    void testGetRid() throws SmbException {
        // Create a mock RPC SID to simulate a user SID
        rpc.sid_t rpcSid = new rpc.sid_t();
        rpcSid.revision = 1;
        rpcSid.sub_authority_count = 5; // Fixed: should be 5 for domain SID with RID
        rpcSid.identifier_authority = new byte[] { 0, 0, 0, 0, 0, 5 };
        rpcSid.sub_authority = new int[] { 21, 123, 456, 789, 1000 };

        SID userSid = new SID(rpcSid, SID.SID_TYPE_USER, "MYDOMAIN", "user", false);
        assertEquals(1000, userSid.getRid());
    }

    /**
     * Test getting the RID from a domain SID.
     *
     * @throws SmbException if the SID string is invalid
     */
    @Test
    void testGetRidOnDomainSid() throws SmbException {
        // Create a mock RPC SID to simulate a domain SID
        rpc.sid_t rpcSid = new rpc.sid_t();
        rpcSid.revision = 1;
        rpcSid.sub_authority_count = 4; // Fixed: should be 4 to properly represent domain SID
        rpcSid.identifier_authority = new byte[] { 0, 0, 0, 0, 0, 5 };
        rpcSid.sub_authority = new int[] { 21, 123, 456, 789 };

        SID domainSid = new SID(rpcSid, SID.SID_TYPE_DOMAIN, "MYDOMAIN", null, true);
        assertThrows(IllegalArgumentException.class, domainSid::getRid);
    }

    /**
     * Test getting the account name.
     */
    @Test
    void testGetAccountName() {
        rpc.sid_t rpcSid = new rpc.sid_t();
        SID sid = new SID(rpcSid, SID.SID_TYPE_USER, "DOMAIN", "user", false);
        assertEquals("user", sid.getAccountName());

        SID domainSid = new SID(rpcSid, SID.SID_TYPE_DOMAIN, "DOMAIN", null, false);
        assertEquals("", domainSid.getAccountName());

        SID unknownSid = new SID(rpcSid, SID.SID_TYPE_UNKNOWN, null, null, false);
        unknownSid.sub_authority_count = 1;
        unknownSid.sub_authority = new int[] { 123 };
        assertEquals("123", unknownSid.getAccountName());
    }

    /**
     * Test getting the SID type as text.
     */
    @Test
    void testGetTypeText() {
        rpc.sid_t rpcSid = new rpc.sid_t();
        SID sid = new SID(rpcSid, SID.SID_TYPE_DOM_GRP, null, null, false);
        assertEquals("Domain group", sid.getTypeText());
    }

    /**
     * Test the unwrap method.
     *
     * @throws SmbException if the SID string is invalid
     */
    @Test
    void testUnwrap() throws SmbException {
        SID sid = new SID(adminSidString);
        SID unwrapped = sid.unwrap(SID.class);
        assertNotNull(unwrapped);
        assertEquals(sid, unwrapped);

        assertThrows(ClassCastException.class, () -> sid.unwrap(String.class));
    }

    /**
     * Test the resolve method.
     *
     * @throws IOException if an I/O error occurs
     */
    @Test
    void testResolve() throws IOException {
        CIFSContext mockContext = mock(CIFSContext.class);
        SidResolver mockResolver = mock(SidResolver.class);
        when(mockContext.getSIDResolver()).thenReturn(mockResolver);

        SID sid = new SID(adminSidString);
        String server = "myserver";
        sid.resolve(server, mockContext);

        ArgumentCaptor<jcifs.SID[]> sidArrayCaptor = ArgumentCaptor.forClass(jcifs.SID[].class);
        verify(mockResolver).resolveSids(eq(mockContext), eq(server), sidArrayCaptor.capture());
        assertEquals(1, sidArrayCaptor.getValue().length);
        assertEquals(sid, sidArrayCaptor.getValue()[0]);
    }

    /**
     * Test getting group members.
     *
     * @throws IOException if an I/O error occurs
     * @throws SmbException if the SID string is invalid
     */
    @Test
    void testGetGroupMemberSids() throws IOException, SmbException {
        CIFSContext mockContext = mock(CIFSContext.class);
        SidResolver mockResolver = mock(SidResolver.class);
        when(mockContext.getSIDResolver()).thenReturn(mockResolver);

        // Create a mock RPC SID to simulate a domain group SID
        rpc.sid_t rpcSid = new rpc.sid_t();
        rpcSid.revision = 1;
        rpcSid.sub_authority_count = 2;
        rpcSid.identifier_authority = new byte[] { 0, 0, 0, 0, 0, 5 };
        rpcSid.sub_authority = new int[] { 32, 544 };

        SID groupSid = new SID(rpcSid, SID.SID_TYPE_DOM_GRP, "BUILTIN", "Administrators", false);

        String server = "myserver";
        int flags = 0;
        groupSid.getGroupMemberSids(server, mockContext, flags);

        verify(mockResolver).getGroupMemberSids(mockContext, server, groupSid.getDomainSid(), groupSid.getRid(), flags);
    }

    /**
     * Test getting group members for a non-group SID.
     *
     * @throws IOException if an I/O error occurs
     * @throws SmbException if the SID string is invalid
     */
    @Test
    void testGetGroupMemberSidsForNonGroup() throws IOException, SmbException {
        // Create a mock RPC SID to simulate a user SID
        rpc.sid_t rpcSid = new rpc.sid_t();
        rpcSid.revision = 1;
        rpcSid.sub_authority_count = 5; // Fixed: should be 5 for domain SID with RID
        rpcSid.identifier_authority = new byte[] { 0, 0, 0, 0, 0, 5 };
        rpcSid.sub_authority = new int[] { 21, 123, 456, 789, 1000 };

        SID userSid = new SID(rpcSid, SID.SID_TYPE_USER, "MYDOMAIN", "user", false);

        jcifs.SID[] members = userSid.getGroupMemberSids("myserver", null, 0);
        assertEquals(0, members.length);
    }

    /**
     * Test static well-known SIDs.
     */
    @Test
    void testWellKnownSids() {
        assertNotNull(SID.EVERYONE);
        assertEquals("S-1-1-0", SID.EVERYONE.toString());

        assertNotNull(SID.CREATOR_OWNER);
        assertEquals("S-1-3-0", SID.CREATOR_OWNER.toString());

        assertNotNull(SID.SYSTEM);
        assertEquals("S-1-5-18", SID.SYSTEM.toString());
    }
}