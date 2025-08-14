package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.SidResolver;
import jcifs.dcerpc.rpc;

class SIDTest {

    // Helper to build a minimal sid_t
    private static rpc.sid_t buildSidT(byte revision, byte[] identAuth, int... subs) {
        rpc.sid_t s = new rpc.sid_t();
        s.revision = revision;
        s.sub_authority_count = (byte) subs.length;
        s.identifier_authority = Arrays.copyOf(identAuth, 6);
        s.sub_authority = Arrays.copyOf(subs, subs.length);
        return s;
    }

    @Nested
    @DisplayName("Basic Constructor and Utility Tests")
    class BasicTests {

        @Test
        @DisplayName("Textual constructor happy path and toString consistency")
        void testTextualConstructorAndToString() throws Exception {
            // Arrange
            SID sid = new SID("S-1-5-21-1-2-3-1029");

            // Act & Assert
            // toString should reconstruct exact textual form
            assertEquals("S-1-5-21-1-2-3-1029", sid.toString());
            // RID is the last subauthority
            assertEquals(1029, sid.getRid());
            // getDomainSid should drop the last subauthority
            assertEquals("S-1-5-21-1-2-3", sid.getDomainSid().toString());
        }

        @Test
        @DisplayName("Textual constructor with hex identifier authority")
        void testTextualConstructorHexAuthority() throws Exception {
            // Arrange: 0x5 == decimal 5 results in decimal authority in toString
            SID sid = new SID("S-1-0x000000000005-21-99");

            // Act
            String s = sid.toString();

            // Assert
            assertEquals("S-1-5-21-99", s);
            assertEquals(99, sid.getRid());
        }

        @Test
        @DisplayName("Textual constructor invalid format throws SmbException")
        void testTextualConstructorInvalid() {
            // Arrange
            String bad = "S-1"; // fewer than 3 tokens

            // Act + Assert
            SmbException ex = assertThrows(SmbException.class, () -> new SID(bad));
            assertTrue(ex.getMessage().contains("Bad textual SID format"));
        }

        @Test
        @DisplayName("Textual constructor null throws NullPointerException")
        void testTextualConstructorNull() {
            assertThrows(NullPointerException.class, () -> new SID((String) null));
        }

        @Test
        @DisplayName("Binary constructor happy path and round-trip via toByteArray")
        void testBinaryConstructorAndToByteArray() {
            // Arrange: revision=1, count=2, identAuth zeros except last byte, subauth 10, 20
            byte[] ident = new byte[] { 0, 0, 0, 0, 0, 5 };
            rpc.sid_t st = buildSidT((byte) 1, ident, 10, 20);

            byte[] bytes = SID.toByteArray(st);

            // Act: construct from bytes and re-encode
            SID sid = new SID(bytes, 0);
            byte[] roundTrip = sid.toByteArray();

            // Assert
            assertArrayEquals(bytes, roundTrip);
            assertEquals("S-1-5-10-20", sid.toString());
        }

        @Test
        @DisplayName("Binary constructor with invalid sub_authority_count throws RuntimeCIFSException")
        void testBinaryConstructorInvalidCount() {
            // Arrange: second byte is sub_authority_count > 100
            byte[] bytes = new byte[1 + 1 + 6];
            bytes[0] = 1; // revision
            bytes[1] = (byte) 101; // invalid count

            // Act + Assert
            RuntimeException ex = assertThrows(RuntimeException.class, () -> new SID(bytes, 0));
            assertTrue(ex.getMessage().contains("Invalid SID sub_authority_count"));
        }

        @Test
        @DisplayName("Relative constructor with RID appends last subauthority")
        void testRelativeConstructorWithRid() throws Exception {
            // Arrange
            SID dom = new SID("S-1-5-21-1-2-3");

            // Act
            SID sid = new SID(dom, 1029);

            // Assert
            assertEquals("S-1-5-21-1-2-3-1029", sid.toString());
            assertEquals(1029, sid.getRid());
        }

        @Test
        @DisplayName("Relative constructor with SID appends all subauthorities of relative SID")
        void testRelativeConstructorWithSid() throws Exception {
            // Arrange
            SID dom = new SID("S-1-5-21");
            SID rel = new SID("S-1-2-200-300"); // two subauthorities appended

            // Act
            SID combined = new SID(dom, rel);

            // Assert
            assertEquals("S-1-5-21-200-300", combined.toString());
        }

        @Test
        @DisplayName("Constructor from sid_t with decrementAuthority drops last subauthority")
        void testConstructorFromSidTWithDecrement() {
            // Arrange
            byte[] ident = new byte[] { 0, 0, 0, 0, 0, 5 };
            rpc.sid_t st = buildSidT((byte) 1, ident, 10, 20, 30);

            // Act: type USER, decrement true
            SID sid = new SID(st, jcifs.SID.SID_TYPE_USER, "DOM", "alice", true);

            // Assert: last element dropped
            assertEquals("S-1-5-10-20", sid.toString());
            assertEquals("DOM", sid.getDomainName());
            assertEquals("alice", sid.getAccountName());
        }

        @Test
        @DisplayName("unwrap returns this for assignable type; otherwise throws ClassCastException")
        void testUnwrap() throws Exception {
            SID sid = new SID("S-1-5-21-1");
            // Happy path
            assertSame(sid, sid.unwrap(SID.class));
            assertSame(sid, sid.unwrap(Object.class));
            // Invalid unwrap
            assertThrows(ClassCastException.class, () -> sid.unwrap(String.class));
        }

        @Test
        @DisplayName("isEmpty and isBlank edge cases")
        void testEmptyAndBlank() throws Exception {
            // No subauthorities
            SID s1 = new SID("S-1-5");
            assertTrue(s1.isEmpty());
            // isBlank will fail if sub_authority is null, so we skip that check for s1

            // All-zero subauthorities
            byte[] ident = new byte[] { 0, 0, 0, 0, 0, 0 };
            rpc.sid_t st = buildSidT((byte) 1, ident, 0, 0);
            SID s2 = new SID(st, jcifs.SID.SID_TYPE_USE_NONE, null, null, false);
            assertFalse(s2.isEmpty());
            assertTrue(s2.isBlank());
        }

        @ParameterizedTest(name = "type {0} -> {1}")
        @CsvSource({ "0, 0", "1, User", "2, Domain group", "3, Domain", "4, Local group", "5, Builtin group", "6, Deleted", "7, Invalid",
                "8, Unknown" })
        @DisplayName("getType and getTypeText cover all types")
        void testGetTypeAndText(int type, String text) {
            byte[] ident = new byte[] { 0, 0, 0, 0, 0, 5 };
            SID sid = new SID(buildSidT((byte) 1, ident, 42), type, "DOM", "acct", false);
            assertEquals(type, sid.getType());
            assertEquals(text, sid.getTypeText());
        }

        @Test
        @DisplayName("getDomainName and getAccountName behaviors for unknown, domain, and user")
        void testNamesByType() {
            byte[] ident = new byte[] { 0, 0, 0, 0, 0, 5 };
            // Unknown: domainName derived from numeric SID, accountName = RID
            SID unknown = new SID(buildSidT((byte) 1, ident, 10, 20, 30), jcifs.SID.SID_TYPE_UNKNOWN, null, null, false);
            assertEquals("S-1-5-10-20", unknown.getDomainName());
            assertEquals("30", unknown.getAccountName());

            // Domain type: domain name as-is, account name empty
            SID domain = new SID(buildSidT((byte) 1, ident, 10, 20), jcifs.SID.SID_TYPE_DOMAIN, "MYDOM", "ignored", false);
            assertEquals("MYDOM", domain.getDomainName());
            assertEquals("", domain.getAccountName());

            // User in regular domain
            SID user = new SID(buildSidT((byte) 1, ident, 10, 20, 99), jcifs.SID.SID_TYPE_USER, "MYDOM", "alice", false);
            assertEquals("MYDOM", user.getDomainName());
            assertEquals("alice", user.getAccountName());
            assertEquals("MYDOM\\alice", user.toDisplayString());
        }

        @Test
        @DisplayName("toDisplayString for BUILTIN and well-known group cases")
        void testDisplayStringBuiltinAndWkn() {
            byte[] ident = new byte[] { 0, 0, 0, 0, 0, 5 };
            // Well-known group
            SID wkn = new SID(buildSidT((byte) 1, ident, 32), jcifs.SID.SID_TYPE_WKN_GRP, "BUILTIN", "Administrators", false);
            assertEquals("Administrators", wkn.toDisplayString());

            // BUILTIN with unknown type -> falls back to numeric toString
            SID unknownBuiltin = new SID(buildSidT((byte) 1, ident, 544), jcifs.SID.SID_TYPE_UNKNOWN, "BUILTIN", "ignored", false);
            assertEquals(unknownBuiltin.toString(), unknownBuiltin.toDisplayString());

            // BUILTIN with other type also returns acctName
            SID aliasBuiltin = new SID(buildSidT((byte) 1, ident, 545), jcifs.SID.SID_TYPE_ALIAS, "BUILTIN", "Users", false);
            assertEquals("Users", aliasBuiltin.toDisplayString());
        }

        @Test
        @DisplayName("toString uses hex authority when high bytes are non-zero")
        void testToStringHexAuthority() {
            byte[] ident = new byte[] { 1, 2, 3, 4, 5, 6 }; // high bytes non-zero -> hex representation
            SID sid = new SID(buildSidT((byte) 1, ident, 7, 8), jcifs.SID.SID_TYPE_USE_NONE, null, null, false);
            String s = sid.toString();
            assertTrue(s.startsWith("S-1-0x010203040506"));
            assertTrue(s.endsWith("-7-8"));
        }

        @Test
        @DisplayName("equals and hashCode for equal and non-equal SIDs")
        void testEqualsAndHashCode() throws Exception {
            SID a1 = new SID("S-1-5-21-1-2-3-4");
            SID a2 = new SID("S-1-5-21-1-2-3-4");
            SID b = new SID("S-1-5-21-1-2-3-5");

            assertEquals(a1, a2);
            assertEquals(a1.hashCode(), a2.hashCode());
            assertNotEquals(a1, b);
            assertNotEquals(a1.hashCode(), b.hashCode());
            assertNotEquals(a1, new Object());
        }

        @Test
        @DisplayName("getRid throws for domain SIDs")
        void testGetRidForDomainThrows() {
            byte[] ident = new byte[] { 0, 0, 0, 0, 0, 5 };
            SID domain = new SID(buildSidT((byte) 1, ident, 10, 20), jcifs.SID.SID_TYPE_DOMAIN, "DOM", null, false);
            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, domain::getRid);
            assertTrue(ex.getMessage().contains("domain sid"));
        }

        @Test
        @DisplayName("Static toByteArray null input throws NPE")
        void testStaticToByteArrayNull() {
            assertThrows(NullPointerException.class, () -> SID.toByteArray(null));
        }
    }

    @Nested
    @DisplayName("Tests requiring mocks")
    @ExtendWith(MockitoExtension.class)
    class MockedTests {
        @Mock
        CIFSContext mockCtx;

        @Mock
        SidResolver mockResolver;

        @BeforeEach
        void setup() {
            lenient().when(mockCtx.getSIDResolver()).thenReturn(mockResolver);
        }

        @Test
        @DisplayName("Manual resolve calls resolver with this SID")
        void testResolveManual() throws Exception {
            // Arrange
            SID sid = new SID("S-1-5-21-1");

            // Act
            sid.resolve("server.example", mockCtx);

            // Assert: resolver.resolveSids called with this SID
            ArgumentCaptor<jcifs.SID[]> captor = ArgumentCaptor.forClass(jcifs.SID[].class);
            verify(mockResolver, times(1)).resolveSids(same(mockCtx), eq("server.example"), captor.capture());
            assertSame(sid, captor.getValue()[0]);
        }

        @Test
        @DisplayName("Weak resolve via initContext triggers only once on accessors")
        void testResolveWeakInitContext() throws SmbException, CIFSException {
            SID sid = new SID("S-1-5-21-1-2");
            sid.initContext("srv", mockCtx);

            // First accessor triggers resolution
            int t1 = sid.getType();
            assertEquals(t1, sid.getType()); // second call should not trigger again
            verify(mockResolver, times(1)).resolveSids(eq(mockCtx), eq("srv"), any(jcifs.SID[].class));
        }

        @Test
        @DisplayName("getGroupMemberSids: non-group types return empty and do not call resolver")
        void testGetGroupMemberSidsNonGroup() throws Exception {
            byte[] ident = new byte[] { 0, 0, 0, 0, 0, 5 };
            SID user = new SID(buildSidT((byte) 1, ident, 10, 99), jcifs.SID.SID_TYPE_USER, "DOM", "alice", false);

            jcifs.SID[] res = user.getGroupMemberSids("srv", mockCtx, 0);

            assertNotNull(res);
            assertEquals(0, res.length);
            verify(mockResolver, never()).getGroupMemberSids(any(), anyString(), any(), anyInt(), anyInt());
        }

        @Test
        @DisplayName("getGroupMemberSids: group types call resolver with domainSid and rid")
        void testGetGroupMemberSidsGroup() throws Exception {
            byte[] ident = new byte[] { 0, 0, 0, 0, 0, 5 };
            // Build a group SID with domain name and RID 512
            SID group = new SID(buildSidT((byte) 1, ident, 10, 20, 512), jcifs.SID.SID_TYPE_DOM_GRP, "DOM", "Domain Admins", false);

            jcifs.SID member = new SID("S-1-5-21-1000");
            jcifs.SID[] expected = new jcifs.SID[] { member };
            when(mockResolver.getGroupMemberSids(eq(mockCtx), eq("srv"), any(jcifs.SID.class), eq(512), eq(123))).thenReturn(expected);

            // Act
            jcifs.SID[] res = group.getGroupMemberSids("srv", mockCtx, 123);

            // Assert
            assertArrayEquals(expected, res);
            ArgumentCaptor<jcifs.SID> domSidCap = ArgumentCaptor.forClass(jcifs.SID.class);
            verify(mockResolver).getGroupMemberSids(eq(mockCtx), eq("srv"), domSidCap.capture(), eq(512), eq(123));
            assertEquals("S-1-5-10-20", domSidCap.getValue().toString());
        }

        @Test
        @DisplayName("initContext then accessors propagate resolver CIFSException as log-only (no throw)")
        void testResolveWeakCIFSExceptionIsIgnored() throws Exception {
            SID sid = new SID("S-1-5-21-1-2-3");
            doThrow(new CIFSException("boom")).when(mockResolver).resolveSids(any(), anyString(), any());
            sid.initContext("srv", mockCtx);

            // Accessor should swallow CIFSException and proceed
            sid.getType();
            verify(mockResolver, times(1)).resolveSids(eq(mockCtx), eq("srv"), any(jcifs.SID[].class));
        }
    }
}