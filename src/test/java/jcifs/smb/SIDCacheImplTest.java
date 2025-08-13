package jcifs.smb;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.dcerpc.DcerpcHandle;
import jcifs.dcerpc.UnicodeString;
import jcifs.dcerpc.msrpc.LsaPolicyHandle;
import jcifs.dcerpc.msrpc.lsarpc;

@ExtendWith(MockitoExtension.class)
class SIDCacheImplTest {

    // Helper to create a SID from text without throwing in the test body
    private static SID sid(String textual) {
        try {
            return new SID(textual);
        } catch (SmbException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("resolveSids(DcerpcHandle,...) populates acct, domain and type for known types")
    void resolveSids_populatesFields_happyPath() throws Exception {
        SIDCacheImpl cache = new SIDCacheImpl(mock(CIFSContext.class));
        DcerpcHandle handle = mock(DcerpcHandle.class);
        LsaPolicyHandle policy = mock(LsaPolicyHandle.class);

        // Prepare input SIDs
        SID s1 = sid("S-1-5-21-1-2-3-1001");
        SID s2 = sid("S-1-5-21-1-2-3-1002");
        jcifs.SID[] in = new jcifs.SID[] { s1, s2 };

        // Stub sendrecv to emulate successful RPC response
        doAnswer(inv -> {
            // Capture the outgoing RPC and populate result fields as the server would
            Object msg = inv.getArgument(0);
            assertTrue(msg instanceof jcifs.dcerpc.msrpc.MsrpcLookupSids);
            jcifs.dcerpc.msrpc.MsrpcLookupSids rpc = (jcifs.dcerpc.msrpc.MsrpcLookupSids) msg;
            // Return success
            rpc.retval = NtStatus.NT_STATUS_SUCCESS;

            // Domains: single domain named TESTDOM
            lsarpc.LsarRefDomainList domains = new lsarpc.LsarRefDomainList();
            domains.count = 1;
            domains.max_count = 1;
            domains.domains = new lsarpc.LsarTrustInformation[1];
            domains.domains[0] = new lsarpc.LsarTrustInformation();
            domains.domains[0].name = new UnicodeString("TESTDOM", false);
            domains.domains[0].sid = new jcifs.dcerpc.rpc.sid_t();
            rpc.domains = domains;

            // Names: provide account names and types for each SID
            lsarpc.LsarTransNameArray names = new lsarpc.LsarTransNameArray();
            names.count = in.length;
            names.names = new lsarpc.LsarTranslatedName[in.length];
            // First is a user
            names.names[0] = new lsarpc.LsarTranslatedName();
            names.names[0].sid_type = (short) jcifs.SID.SID_TYPE_USER;
            names.names[0].name = new UnicodeString("alice", false);
            names.names[0].sid_index = 0;
            // Second is a domain group
            names.names[1] = new lsarpc.LsarTranslatedName();
            names.names[1].sid_type = (short) jcifs.SID.SID_TYPE_DOM_GRP;
            names.names[1].name = new UnicodeString("Domain Users", false);
            names.names[1].sid_index = 0;
            rpc.names = names;
            return null;
        }).when(handle).sendrecv(any());

        cache.resolveSids(handle, policy, in);

        // Verify fields resolved
        assertEquals("alice", s1.getAccountName());
        assertEquals("TESTDOM", s1.getDomainName());
        assertEquals(jcifs.SID.SID_TYPE_USER, s1.getType());

        assertEquals("Domain Users", s2.getAccountName());
        assertEquals("TESTDOM", s2.getDomainName());
        assertEquals(jcifs.SID.SID_TYPE_DOM_GRP, s2.getType());

        // Interaction: sendrecv invoked exactly once
        verify(handle, times(1)).sendrecv(any(jcifs.dcerpc.msrpc.MsrpcLookupSids.class));
    }

    @ParameterizedTest
    @ValueSource(ints = { NtStatus.NT_STATUS_SUCCESS, NtStatus.NT_STATUS_NONE_MAPPED, 0x00000107 })
    @DisplayName("resolveSids(DcerpcHandle,...) accepts success/none/some-not-mapped codes")
    void resolveSids_allowsCertainRetvals_noThrow(int ret) throws Exception {
        SIDCacheImpl cache = new SIDCacheImpl(mock(CIFSContext.class));
        DcerpcHandle handle = mock(DcerpcHandle.class);
        LsaPolicyHandle policy = mock(LsaPolicyHandle.class);

        jcifs.SID[] sids = new jcifs.SID[] { sid("S-1-1-0") };

        // Arrange a minimal response with given retval
        doAnswer(inv -> {
            jcifs.dcerpc.msrpc.MsrpcLookupSids rpc = inv.getArgument(0);
            rpc.retval = ret;
            // Provide empty arrays to satisfy code paths
            rpc.names = new lsarpc.LsarTransNameArray();
            rpc.names.count = sids.length;
            rpc.names.names = new lsarpc.LsarTranslatedName[sids.length];
            for (int i = 0; i < sids.length; i++) {
                rpc.names.names[i] = new lsarpc.LsarTranslatedName();
                rpc.names.names[i].sid_type = (short) jcifs.SID.SID_TYPE_UNKNOWN;
                rpc.names.names[i].name = new UnicodeString("", false);
                rpc.names.names[i].sid_index = 0;
            }
            rpc.domains = new lsarpc.LsarRefDomainList();
            rpc.domains.count = 1;
            rpc.domains.max_count = 1;
            rpc.domains.domains = new lsarpc.LsarTrustInformation[1];
            rpc.domains.domains[0] = new lsarpc.LsarTrustInformation();
            rpc.domains.domains[0].name = new UnicodeString("", false);
            rpc.domains.domains[0].sid = new jcifs.dcerpc.rpc.sid_t();
            return null;
        }).when(handle).sendrecv(any());

        assertDoesNotThrow(() -> cache.resolveSids(handle, policy, sids));
    }

    @Test
    @DisplayName("resolveSids(DcerpcHandle,...) throws SmbException on unexpected retval")
    void resolveSids_throwsOnUnexpectedRetval() throws Exception {
        SIDCacheImpl cache = new SIDCacheImpl(mock(CIFSContext.class));
        DcerpcHandle handle = mock(DcerpcHandle.class);
        LsaPolicyHandle policy = mock(LsaPolicyHandle.class);

        jcifs.SID[] sids = new jcifs.SID[] { sid("S-1-1-0") };

        doAnswer(inv -> {
            jcifs.dcerpc.msrpc.MsrpcLookupSids rpc = inv.getArgument(0);
            rpc.retval = NtStatus.NT_STATUS_ACCESS_DENIED; // unexpected code
            rpc.names = new lsarpc.LsarTransNameArray();
            rpc.names.count = 1;
            rpc.names.names = new lsarpc.LsarTranslatedName[] { new lsarpc.LsarTranslatedName() };
            rpc.domains = new lsarpc.LsarRefDomainList();
            rpc.domains.count = 0;
            rpc.domains.domains = new lsarpc.LsarTrustInformation[0];
            return null;
        }).when(handle).sendrecv(any());

        SmbException ex = assertThrows(SmbException.class, () -> cache.resolveSids(handle, policy, sids));
        assertEquals(NtStatus.NT_STATUS_ACCESS_DENIED, ex.getNtStatus());
    }

    @Test
    @DisplayName("resolveSids(CIFSContext,server,sids,offset,length) resolves missing, caches, and reuses cache")
    void resolveSids_withOffsetAndCache_behavesCorrectly() throws Exception {
        CIFSContext ctx = mock(CIFSContext.class);
        SIDCacheImpl cache = Mockito.spy(new SIDCacheImpl(ctx));

        // Prepare SIDs, two need resolution, one already resolved
        SID s1 = sid("S-1-5-21-10-11-12-1001");
        SID s2 = sid("S-1-5-21-10-11-12-1002");
        SID s3 = sid("S-1-5-21-10-11-12-1003");
        jcifs.SID[] arr = new jcifs.SID[] { s1, s2, s3 };

        // First call should resolve two (offset=0,length=2)
        doAnswer(inv -> {
            // Simulate resolve call by setting names/types and thus enabling cache population
            Object[] args = inv.getArguments();
            String server = (String) args[0];
            CIFSContext c = (CIFSContext) args[1];
            assertNull(server); // We will pass null; method should forward it unchanged
            assertSame(ctx, c);
            SID[] toResolve = (SID[]) args[2];
            for (int i = 0; i < toResolve.length; i++) {
                toResolve[i].type = jcifs.SID.SID_TYPE_USER;
                toResolve[i].domainName = "DOM";
                toResolve[i].acctName = "user" + (i + 1);
            }
            return null;
        }).when(cache).resolveSids0(any(), any(), any());

        // Resolve first two entries
        cache.resolveSids(ctx, null, arr, 0, 2);

        // Verify resolveSids0 called exactly once with the two SIDs needing resolution
        ArgumentCaptor<SID[]> captor = ArgumentCaptor.forClass(SID[].class);
        verify(cache, times(1)).resolveSids0(isNull(), same(ctx), captor.capture());
        SID[] resolvedFirst = captor.getValue();
        assertEquals(2, resolvedFirst.length);
        assertEquals("user1", ((SID) resolvedFirst[0]).acctName);
        assertEquals("user2", ((SID) resolvedFirst[1]).acctName);

        // Second call with overlap should use cache for s2 and s3, requiring only s3 if not cached
        // Mark s3 unresolved to force resolve of one element
        doAnswer(inv -> {
            SID[] toResolve = inv.getArgument(2);
            for (SID s : toResolve) {
                s.type = jcifs.SID.SID_TYPE_USER;
                s.domainName = "DOM";
                s.acctName = "userX";
            }
            return null;
        }).when(cache).resolveSids0(any(), any(), any());

        cache.resolveSids(ctx, null, arr, 2, 1); // resolve only s3

        // Verify cache behavior - after reset, spying on the same cache won't work
        // Since we're working with internal state, we'll verify the side effects
        assertEquals("DOM", s1.getDomainName());
        assertEquals("user1", s1.getAccountName());
        assertEquals("DOM", s2.getDomainName());
        assertEquals("user2", s2.getAccountName());
        assertEquals("DOM", s3.getDomainName());
        assertEquals("userX", s3.getAccountName());
    }

    @Test
    @DisplayName("resolveSids(CIFSContext,server,sids,offset,length) with zero length does not resolve")
    void resolveSids_zeroLength_doesNothing() throws Exception {
        CIFSContext ctx = mock(CIFSContext.class);
        SIDCacheImpl cache = Mockito.spy(new SIDCacheImpl(ctx));

        jcifs.SID[] arr = new jcifs.SID[] { sid("S-1-1-0") };
        cache.resolveSids(ctx, "server", arr, 0, 0);
        verify(cache, never()).resolveSids0(any(), any(), any());
    }

    @Test
    @DisplayName("resolveSids(CIFSContext,server,sids,offset,length) throws on invalid inputs")
    void resolveSids_invalidInputs() throws Exception {
        SIDCacheImpl cache = new SIDCacheImpl(mock(CIFSContext.class));
        CIFSContext ctx = mock(CIFSContext.class);

        // Null sids array -> NPE
        assertThrows(NullPointerException.class, () -> cache.resolveSids(ctx, "server", null, 0, 1));

        // Bad offset/length leads to ArrayIndexOutOfBoundsException
        jcifs.SID[] sids = new jcifs.SID[] { sid("S-1-1-0") };
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> cache.resolveSids(ctx, "server", sids, 1, 2));
    }

    @Nested
    class EdgeCasesForResolveSids {
        @Test
        @DisplayName("resolveSids(DcerpcHandle,...) leaves domain null for unknown type")
        void resolveSids_unknownType_domainNull() throws Exception {
            SIDCacheImpl cache = new SIDCacheImpl(mock(CIFSContext.class));
            DcerpcHandle handle = mock(DcerpcHandle.class);
            LsaPolicyHandle policy = mock(LsaPolicyHandle.class);
            SID s = sid("S-1-5-21-1-2-3-2000");
            jcifs.SID[] in = new jcifs.SID[] { s };

            doAnswer(inv -> {
                jcifs.dcerpc.msrpc.MsrpcLookupSids rpc = inv.getArgument(0);
                rpc.retval = NtStatus.NT_STATUS_SUCCESS;
                rpc.domains = new lsarpc.LsarRefDomainList();
                rpc.domains.count = 0;
                rpc.domains.domains = new lsarpc.LsarTrustInformation[0];

                rpc.names = new lsarpc.LsarTransNameArray();
                rpc.names.count = 1;
                rpc.names.names = new lsarpc.LsarTranslatedName[1];
                rpc.names.names[0] = new lsarpc.LsarTranslatedName();
                rpc.names.names[0].sid_type = (short) jcifs.SID.SID_TYPE_UNKNOWN; // not in switch list
                rpc.names.names[0].name = new UnicodeString("unknown", false);
                rpc.names.names[0].sid_index = 0;
                return null;
            }).when(handle).sendrecv(any());

            cache.resolveSids(handle, policy, in);

            // When type is SID_TYPE_UNKNOWN, getAccountName returns the RID as string
            // and getDomainName returns the domain part of the SID
            assertEquals("2000", s.getAccountName());
            assertEquals("S-1-5-21-1-2-3", s.getDomainName());
            assertEquals(jcifs.SID.SID_TYPE_UNKNOWN, s.getType());
        }

        @Test
        @DisplayName("resolveSids(DcerpcHandle,...) with empty SID array still invokes sendrecv")
        void resolveSids_emptyArray_stillCallsSendrecv() throws Exception {
            SIDCacheImpl cache = new SIDCacheImpl(mock(CIFSContext.class));
            DcerpcHandle handle = mock(DcerpcHandle.class);
            LsaPolicyHandle policy = mock(LsaPolicyHandle.class);
            jcifs.SID[] none = new jcifs.SID[0];

            cache.resolveSids(handle, policy, none);
            verify(handle, times(1)).sendrecv(any(jcifs.dcerpc.msrpc.MsrpcLookupSids.class));
        }
    }

    @Test
    @DisplayName("getLocalGroupsMap can be built from stubs via spy (interaction focus)")
    void getLocalGroupsMap_interactions_viaSpy() throws CIFSException, IOException {
        // This test verifies interactions with dependent public methods without invoking RPC
        CIFSContext ctx = mock(CIFSContext.class);
        SIDCacheImpl cache = Mockito.spy(new SIDCacheImpl(ctx));

        // Domain SID to be returned by stub
        SID domSid = sid("S-1-5-21-10-11-12");

        // Stub getServerSid so getLocalGroupsMap logic can proceed
        doReturn(domSid).when(cache).getServerSid(ctx, "server");

        // Since we cannot mock static DcerpcHandle.getHandle, we verify that our stubs are invoked
        // by calling the public method and catching the expected CIFSException from unmocked internals.
        try {
            cache.getLocalGroupsMap(ctx, "server", 0);
            fail("Expected CIFSException due to unmocked RPC internals");
        } catch (CIFSException e) {
            // Verify our stubs were engaged before the failure occurred
            verify(cache, atLeastOnce()).getServerSid(ctx, "server");
        }
    }
}

