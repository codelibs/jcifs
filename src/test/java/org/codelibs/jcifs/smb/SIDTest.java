package org.codelibs.jcifs.smb;

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

import org.codelibs.jcifs.smb.dcerpc.rpc;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * Tests for the SIDObject class.
 */
class SIDTest {

    // A well-known SIDObject for "Administrators"
    private final String adminSidString = "S-1-5-32-544";
    private final byte[] adminSidBytes = new byte[] { 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0 };

    /**
     * Test constructor with a valid SIDObject string.
     *
     * @throws SmbSystemException if the SIDObject string is invalid
     */
    @Test
    void testStringConstructor() throws SmbException {
        SIDObject sid = new SIDObject(adminSidString);
        assertEquals(1, sid.revision);
        assertEquals(2, sid.sub_authority_count);
        assertEquals(5, sid.identifier_authority[5]);
        assertEquals(32, sid.sub_authority[0]);
        assertEquals(544, sid.sub_authority[1]);
        assertEquals(adminSidString, sid.toString());
    }

    /**
     * Test constructor with a SIDObject string containing a hex value.
     *
     * @throws SmbSystemException if the SIDObject string is invalid
     */
    @Test
    void testStringConstructorWithHex() throws SmbException {
        SIDObject sid = new SIDObject("S-1-0x12-21-1");
        assertEquals(1, sid.revision);
        assertEquals(0x12, sid.identifier_authority[5]);
        assertEquals(2, sid.sub_authority_count);
        assertEquals(21, sid.sub_authority[0]);
        assertEquals(1, sid.sub_authority[1]);
    }

    /**
     * Test constructor with an invalid SIDObject string.
     */
    @Test
    void testStringConstructorInvalidFormat() {
        assertThrows(SmbException.class, () -> new SIDObject("invalid-sid"));
        assertThrows(SmbException.class, () -> new SIDObject("S-1"));
    }

    /**
     * Test constructor with a byte array.
     */
    @Test
    void testByteArrayConstructor() {
        SIDObject sid = new SIDObject(adminSidBytes, 0);
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
        assertThrows(RuntimeCIFSException.class, () -> new SIDObject(badSid, 0));
    }

    /**
     * Test constructor that combines a domain SIDObject and an RID.
     *
     * @throws SmbSystemException if the SIDObject string is invalid
     */
    @Test
    void testDomainSidAndRidConstructor() throws SmbException {
        SIDObject domainSid = new SIDObject("S-1-5-21-123-456-789");
        int rid = 1000;
        SIDObject userSid = new SIDObject(domainSid, rid);
        assertEquals("S-1-5-21-123-456-789-1000", userSid.toString());
    }

    /**
     * Test constructor that combines a domain SIDObject and a relative SIDObject.
     *
     * @throws SmbSystemException if the SIDObject string is invalid
     */
    @Test
    void testDomainSidAndRelativeSidConstructor() throws SmbException {
        SIDObject domainSid = new SIDObject("S-1-5-21-123-456-789");
        SIDObject relativeSid = new SIDObject("S-1-5-1000"); // This is not a valid relative SIDObject, but tests the logic
        relativeSid.sub_authority_count = 1;
        relativeSid.sub_authority = new int[] { 1000 };

        SIDObject userSid = new SIDObject(domainSid, relativeSid);
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

        SIDObject sid = new SIDObject(rpcSid, SIDObject.SID_TYPE_WKN_GRP, "BUILTIN", "Administrators", false);
        assertEquals(SIDObject.SID_TYPE_WKN_GRP, sid.getType());
        assertEquals("BUILTIN", sid.getDomainName());
        assertEquals("Administrators", sid.getAccountName());
        assertEquals(adminSidString, sid.toString());
    }

    /**
     * Test converting a SIDObject to a byte array.
     */
    @Test
    void testToByteArray() {
        SIDObject sid = new SIDObject(adminSidBytes, 0);
        assertArrayEquals(adminSidBytes, sid.toByteArray());
    }

    /**
     * Test the equals method.
     *
     * @throws SmbSystemException if the SIDObject string is invalid
     */
    @Test
    void testEquals() throws SmbException {
        SIDObject sid1 = new SIDObject(adminSidString);
        SIDObject sid2 = new SIDObject(adminSidBytes, 0);
        SIDObject sid3 = new SIDObject("S-1-1-0"); // Everyone

        assertEquals(sid1, sid1);
        assertEquals(sid1, sid2);
        assertNotEquals(sid1, sid3);
        assertNotEquals(sid1, null);
        assertNotEquals(sid1, new Object());
    }

    /**
     * Test the hashCode method.
     *
     * @throws SmbSystemException if the SIDObject string is invalid
     */
    @Test
    void testHashCode() throws SmbException {
        SIDObject sid1 = new SIDObject(adminSidString);
        SIDObject sid2 = new SIDObject(adminSidBytes, 0);
        SIDObject sid3 = new SIDObject("S-1-1-0");

        assertEquals(sid1.hashCode(), sid2.hashCode());
        assertNotEquals(sid1.hashCode(), sid3.hashCode());
    }

    /**
     * Test the toDisplayString method for a resolved SIDObject.
     */
    @Test
    void testToDisplayStringResolved() {
        rpc.sid_t rpcSid = new rpc.sid_t();
        rpcSid.revision = 1;
        rpcSid.sub_authority_count = 2;
        rpcSid.identifier_authority = new byte[] { 0, 0, 0, 0, 0, 5 };
        rpcSid.sub_authority = new int[] { 32, 544 };

        SIDObject sid = new SIDObject(rpcSid, SIDObject.SID_TYPE_ALIAS, "MYDOMAIN", "MyAlias", false);
        assertEquals("MYDOMAIN\\MyAlias", sid.toDisplayString());

        SIDObject domainSid = new SIDObject(rpcSid, SIDObject.SID_TYPE_DOMAIN, "MYDOMAIN", null, true);
        assertEquals("MYDOMAIN", domainSid.toDisplayString());

        SIDObject builtinSid = new SIDObject(rpcSid, SIDObject.SID_TYPE_WKN_GRP, "BUILTIN", "Administrators", false);
        assertEquals("Administrators", builtinSid.toDisplayString());
    }

    /**
     * Test the toDisplayString method for an unresolved SIDObject.
     *
     * @throws SmbSystemException if the SIDObject string is invalid
     */
    @Test
    void testToDisplayStringUnresolved() throws SmbException {
        SIDObject sid = new SIDObject(adminSidString);
        assertEquals(adminSidString, sid.toDisplayString());
    }

    /**
     * Test getting the domain SIDObject.
     *
     * @throws SmbSystemException if the SIDObject string is invalid
     */
    @Test
    void testGetDomainSid() throws SmbException {
        // Create a mock RPC SIDObject to simulate a user SIDObject
        rpc.sid_t rpcSid = new rpc.sid_t();
        rpcSid.revision = 1;
        rpcSid.sub_authority_count = 5; // Fixed: should be 5 for domain SIDObject with RID
        rpcSid.identifier_authority = new byte[] { 0, 0, 0, 0, 0, 5 };
        rpcSid.sub_authority = new int[] { 21, 123, 456, 789, 1000 };

        SIDObject userSid = new SIDObject(rpcSid, SIDObject.SID_TYPE_USER, "MYDOMAIN", "user", false);
        SIDObject domainSid = userSid.getDomainSid();
        assertEquals("S-1-5-21-123-456-789", domainSid.toString());
        assertEquals(SIDObject.SID_TYPE_DOMAIN, domainSid.getType());
    }

    /**
     * Test getting the RID.
     *
     * @throws SmbSystemException if the SIDObject string is invalid
     */
    @Test
    void testGetRid() throws SmbException {
        // Create a mock RPC SIDObject to simulate a user SIDObject
        rpc.sid_t rpcSid = new rpc.sid_t();
        rpcSid.revision = 1;
        rpcSid.sub_authority_count = 5; // Fixed: should be 5 for domain SIDObject with RID
        rpcSid.identifier_authority = new byte[] { 0, 0, 0, 0, 0, 5 };
        rpcSid.sub_authority = new int[] { 21, 123, 456, 789, 1000 };

        SIDObject userSid = new SIDObject(rpcSid, SIDObject.SID_TYPE_USER, "MYDOMAIN", "user", false);
        assertEquals(1000, userSid.getRid());
    }

    /**
     * Test getting the RID from a domain SIDObject.
     *
     * @throws SmbSystemException if the SIDObject string is invalid
     */
    @Test
    void testGetRidOnDomainSid() throws SmbException {
        // Create a mock RPC SIDObject to simulate a domain SIDObject
        rpc.sid_t rpcSid = new rpc.sid_t();
        rpcSid.revision = 1;
        rpcSid.sub_authority_count = 4; // Fixed: should be 4 to properly represent domain SIDObject
        rpcSid.identifier_authority = new byte[] { 0, 0, 0, 0, 0, 5 };
        rpcSid.sub_authority = new int[] { 21, 123, 456, 789 };

        SIDObject domainSid = new SIDObject(rpcSid, SIDObject.SID_TYPE_DOMAIN, "MYDOMAIN", null, true);
        assertThrows(IllegalArgumentException.class, domainSid::getRid);
    }

    /**
     * Test getting the account name.
     */
    @Test
    void testGetAccountName() {
        rpc.sid_t rpcSid = new rpc.sid_t();
        SIDObject sid = new SIDObject(rpcSid, SIDObject.SID_TYPE_USER, "DOMAIN", "user", false);
        assertEquals("user", sid.getAccountName());

        SIDObject domainSid = new SIDObject(rpcSid, SIDObject.SID_TYPE_DOMAIN, "DOMAIN", null, false);
        assertEquals("", domainSid.getAccountName());

        SIDObject unknownSid = new SIDObject(rpcSid, SIDObject.SID_TYPE_UNKNOWN, null, null, false);
        unknownSid.sub_authority_count = 1;
        unknownSid.sub_authority = new int[] { 123 };
        assertEquals("123", unknownSid.getAccountName());
    }

    /**
     * Test getting the SIDObject type as text.
     */
    @Test
    void testGetTypeText() {
        rpc.sid_t rpcSid = new rpc.sid_t();
        SIDObject sid = new SIDObject(rpcSid, SIDObject.SID_TYPE_DOM_GRP, null, null, false);
        assertEquals("Domain group", sid.getTypeText());
    }

    /**
     * Test the unwrap method.
     *
     * @throws SmbSystemException if the SIDObject string is invalid
     */
    @Test
    void testUnwrap() throws SmbException {
        SIDObject sid = new SIDObject(adminSidString);
        SIDObject unwrapped = sid.unwrap(SIDObject.class);
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

        SIDObject sid = new SIDObject(adminSidString);
        String server = "myserver";
        sid.resolve(server, mockContext);

        ArgumentCaptor<org.codelibs.jcifs.smb.SID[]> sidArrayCaptor = ArgumentCaptor.forClass(org.codelibs.jcifs.smb.SID[].class);
        verify(mockResolver).resolveSids(eq(mockContext), eq(server), sidArrayCaptor.capture());
        assertEquals(1, sidArrayCaptor.getValue().length);
        assertEquals(sid, sidArrayCaptor.getValue()[0]);
    }

    /**
     * Test getting group members.
     *
     * @throws IOException if an I/O error occurs
     * @throws SmbSystemException if the SIDObject string is invalid
     */
    @Test
    void testGetGroupMemberSids() throws IOException, SmbException {
        CIFSContext mockContext = mock(CIFSContext.class);
        SidResolver mockResolver = mock(SidResolver.class);
        when(mockContext.getSIDResolver()).thenReturn(mockResolver);

        // Create a mock RPC SIDObject to simulate a domain group SIDObject
        rpc.sid_t rpcSid = new rpc.sid_t();
        rpcSid.revision = 1;
        rpcSid.sub_authority_count = 2;
        rpcSid.identifier_authority = new byte[] { 0, 0, 0, 0, 0, 5 };
        rpcSid.sub_authority = new int[] { 32, 544 };

        SIDObject groupSid = new SIDObject(rpcSid, SIDObject.SID_TYPE_DOM_GRP, "BUILTIN", "Administrators", false);

        String server = "myserver";
        int flags = 0;
        groupSid.getGroupMemberSids(server, mockContext, flags);

        verify(mockResolver).getGroupMemberSids(mockContext, server, groupSid.getDomainSid(), groupSid.getRid(), flags);
    }

    /**
     * Test getting group members for a non-group SIDObject.
     *
     * @throws IOException if an I/O error occurs
     * @throws SmbSystemException if the SIDObject string is invalid
     */
    @Test
    void testGetGroupMemberSidsForNonGroup() throws IOException, SmbException {
        // Create a mock RPC SIDObject to simulate a user SIDObject
        rpc.sid_t rpcSid = new rpc.sid_t();
        rpcSid.revision = 1;
        rpcSid.sub_authority_count = 5; // Fixed: should be 5 for domain SIDObject with RID
        rpcSid.identifier_authority = new byte[] { 0, 0, 0, 0, 0, 5 };
        rpcSid.sub_authority = new int[] { 21, 123, 456, 789, 1000 };

        SIDObject userSid = new SIDObject(rpcSid, SIDObject.SID_TYPE_USER, "MYDOMAIN", "user", false);

        org.codelibs.jcifs.smb.SID[] members = userSid.getGroupMemberSids("myserver", null, 0);
        assertEquals(0, members.length);
    }

    /**
     * Test static well-known SIDs.
     */
    @Test
    void testWellKnownSids() {
        assertNotNull(SIDObject.EVERYONE);
        assertEquals("S-1-1-0", SIDObject.EVERYONE.toString());

        assertNotNull(SIDObject.CREATOR_OWNER);
        assertEquals("S-1-3-0", SIDObject.CREATOR_OWNER.toString());

        assertNotNull(SIDObject.SYSTEM);
        assertEquals("S-1-5-18", SIDObject.SYSTEM.toString());
    }
}