package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.SmbSession;

/**
 * Tests for SmbTransportInternal interface using Mockito mocks to
 * exercise method contracts, checked exceptions, and interactions.
 */
@ExtendWith(MockitoExtension.class)
public class SmbTransportInternalTest {

    @Mock
    private SmbTransportInternal transport;

    @Mock
    private jcifs.CIFSContext ctx;

    @Mock
    private SmbSession session;

    @Mock
    private jcifs.DfsReferralData referral;

    @BeforeEach
    void resetMocks() {
        Mockito.reset(transport, ctx, session, referral);
    }

    // Happy path: hasCapability returns based on provided capability codes
    @ParameterizedTest
    @DisplayName("hasCapability returns expected values for various caps")
    @ValueSource(ints = { -1, 0, 1, 1024 })
    void hasCapability_variousCaps(int cap) throws SmbException {
        when(transport.hasCapability(anyInt())).thenAnswer(inv -> ((int) inv.getArgument(0)) >= 0);

        boolean result = transport.hasCapability(cap);

        assertEquals(cap >= 0, result);
        verify(transport, times(1)).hasCapability(cap);
    }

    // Invalid input: simulate underlying SmbException when capability check fails
    @Test
    @DisplayName("hasCapability throws SmbException when underlying error occurs")
    void hasCapability_throws() throws SmbException {
        doThrow(new SmbException("capability check failed")).when(transport).hasCapability(eq(42));
        SmbException ex = assertThrows(SmbException.class, () -> transport.hasCapability(42));
        assertTrue(ex.getMessage().contains("failed"));
        verify(transport).hasCapability(42);
    }

    // Edge: disconnected status toggles
    @ParameterizedTest
    @DisplayName("isDisconnected reflects current mocked state")
    @ValueSource(booleans = { true, false })
    void isDisconnected_states(boolean disconnected) {
        when(transport.isDisconnected()).thenReturn(disconnected);
        assertEquals(disconnected, transport.isDisconnected());
        verify(transport, times(1)).isDisconnected();
    }

    // Happy path + edge: disconnect with all flag combinations
    @ParameterizedTest
    @DisplayName("disconnect returns expected for flag combinations")
    @CsvSource({
            // hard, inuse, expected
            "true,true,false", "true,false,true", "false,true,true", "false,false,false" })
    void disconnect_flagCombinations(boolean hard, boolean inuse, boolean expected) throws Exception {
        when(transport.disconnect(anyBoolean(), anyBoolean())).thenAnswer(inv -> {
            boolean h = inv.getArgument(0);
            boolean u = inv.getArgument(1);
            // Arbitrary behavior mapping for test purposes
            return (h && !u) || (!h && u);
        });

        boolean result = transport.disconnect(hard, inuse);

        assertEquals(expected, result);
        verify(transport, times(1)).disconnect(hard, inuse);
    }

    // Error case: disconnect throws IOException
    @Test
    @DisplayName("disconnect throws IOException when underlying close fails")
    void disconnect_throwsIOException() throws Exception {
        doThrow(new java.io.IOException("close error")).when(transport).disconnect(true, true);
        java.io.IOException ex = assertThrows(java.io.IOException.class, () -> transport.disconnect(true, true));
        assertTrue(ex.getMessage().contains("close"));
        verify(transport).disconnect(true, true);
    }

    // Happy path: ensureConnected returns true/false
    @ParameterizedTest
    @DisplayName("ensureConnected indicates if it connected during call")
    @ValueSource(booleans = { true, false })
    void ensureConnected_returns(boolean connectedDuringCall) throws Exception {
        when(transport.ensureConnected()).thenReturn(connectedDuringCall);
        assertEquals(connectedDuringCall, transport.ensureConnected());
        verify(transport).ensureConnected();
    }

    // Error case: ensureConnected throws IOException
    @Test
    @DisplayName("ensureConnected throws IOException on failure")
    void ensureConnected_throwsIOException() throws Exception {
        doThrow(new java.io.IOException("connect failed")).when(transport).ensureConnected();
        java.io.IOException ex = assertThrows(java.io.IOException.class, () -> transport.ensureConnected());
        assertTrue(ex.getMessage().contains("connect"));
        verify(transport).ensureConnected();
    }

    // Happy path: getDfsReferrals returns referral, verify arguments captured
    @Test
    @DisplayName("getDfsReferrals returns data and receives correct args")
    void getDfsReferrals_happy() throws Exception {
        when(transport.getDfsReferrals(any(), any(), any(), any(), anyInt())).thenReturn(referral);

        String name = "\\\\server\\\\share\\\\path"; // UNC-like DFS path
        String host = "server.example";
        String domain = "EXAMPLE";
        int rn = 0;

        jcifs.DfsReferralData result = transport.getDfsReferrals(ctx, name, host, domain, rn);

        assertSame(referral, result);

        ArgumentCaptor<String> nameCap = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> hostCap = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> domCap = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Integer> rnCap = ArgumentCaptor.forClass(Integer.class);

        verify(transport).getDfsReferrals(eq(ctx), nameCap.capture(), hostCap.capture(), domCap.capture(), rnCap.capture());
        assertEquals(name, nameCap.getValue());
        assertEquals(host, hostCap.getValue());
        assertEquals(domain, domCap.getValue());
        assertEquals(rn, rnCap.getValue());
    }

    // Edge case: test with empty name
    @Test
    @DisplayName("getDfsReferrals handles empty name via CIFSException")
    void getDfsReferrals_emptyName() throws Exception {
        String emptyName = "";
        doThrow(new jcifs.CIFSException("invalid dfs name")).when(transport)
                .getDfsReferrals(eq(ctx), eq(emptyName), any(), any(), anyInt());

        assertThrows(jcifs.CIFSException.class, () -> transport.getDfsReferrals(ctx, emptyName, "h", "d", 1));
        verify(transport).getDfsReferrals(eq(ctx), eq(emptyName), eq("h"), eq("d"), eq(1));
    }

    // Edge case: test with null name
    @Test
    @DisplayName("getDfsReferrals handles null name via CIFSException")
    void getDfsReferrals_nullName() throws Exception {
        String nullName = null;
        doThrow(new jcifs.CIFSException("invalid dfs name")).when(transport).getDfsReferrals(eq(ctx), isNull(), any(), any(), anyInt());

        assertThrows(jcifs.CIFSException.class, () -> transport.getDfsReferrals(ctx, nullName, "h", "d", 1));
        verify(transport).getDfsReferrals(eq(ctx), isNull(), eq("h"), eq("d"), eq(1));
    }

    // Signing modes: optional vs enforced
    @Test
    @DisplayName("isSigningOptional and isSigningEnforced reflect configuration")
    void signingModes() throws Exception {
        when(transport.isSigningOptional()).thenReturn(true);
        when(transport.isSigningEnforced()).thenReturn(false);

        assertTrue(transport.isSigningOptional());
        assertFalse(transport.isSigningEnforced());
        verify(transport).isSigningOptional();
        verify(transport).isSigningEnforced();
    }

    // Error propagation: signing checks may throw SmbException
    @Test
    @DisplayName("signing checks propagate SmbException")
    void signingChecks_throw() throws Exception {
        doThrow(new SmbException("opt error")).when(transport).isSigningOptional();
        doThrow(new SmbException("enf error")).when(transport).isSigningEnforced();

        assertThrows(SmbException.class, () -> transport.isSigningOptional());
        assertThrows(SmbException.class, () -> transport.isSigningEnforced());
        verify(transport).isSigningOptional();
        verify(transport).isSigningEnforced();
    }

    // Happy path and edge: server encryption key can be non-null, empty, or null
    @Test
    @DisplayName("getServerEncryptionKey returns expected bytes")
    void serverEncryptionKey_variants() {
        byte[] key = new byte[] { 1, 2, 3 };
        when(transport.getServerEncryptionKey()).thenReturn(key);
        assertArrayEquals(key, transport.getServerEncryptionKey());
        verify(transport).getServerEncryptionKey();

        // Empty array
        byte[] empty = new byte[0];
        when(transport.getServerEncryptionKey()).thenReturn(empty);
        assertArrayEquals(empty, transport.getServerEncryptionKey());

        // Null
        when(transport.getServerEncryptionKey()).thenReturn(null);
        assertNull(transport.getServerEncryptionKey());
    }

    // Happy path: session retrieval by context
    @Test
    @DisplayName("getSmbSession(ctx) returns a session and verifies argument")
    void getSmbSession_byContext() {
        when(transport.getSmbSession(any(jcifs.CIFSContext.class))).thenReturn(session);
        SmbSession result = transport.getSmbSession(ctx);
        assertSame(session, result);
        verify(transport).getSmbSession(eq(ctx));
    }

    // Edge inputs: null context returns null session per mock setup
    @Test
    @DisplayName("getSmbSession(ctx) with null context returns null as stubbed")
    void getSmbSession_byContext_null() {
        when(transport.getSmbSession(isNull(jcifs.CIFSContext.class))).thenReturn(null);
        assertNull(transport.getSmbSession((jcifs.CIFSContext) null));
        verify(transport).getSmbSession((jcifs.CIFSContext) isNull());
    }

    // Happy path: session retrieval with host/domain variations
    @ParameterizedTest
    @DisplayName("getSmbSession(ctx,host,domain) returns session for various inputs")
    @CsvSource({ "server,DOMAIN", "server,", ",DOMAIN", "," })
    void getSmbSession_withTarget(String host, String domain) {
        when(transport.getSmbSession(any(jcifs.CIFSContext.class), any(), any())).thenReturn(session);
        SmbSession result = transport.getSmbSession(ctx, host, domain);
        assertSame(session, result);
        verify(transport).getSmbSession(eq(ctx), eq(host), eq(domain));
    }

    // SMB2 detection: true/false and exception path
    @Test
    @DisplayName("isSMB2 returns true/false and can throw")
    void isSMB2_variants() throws Exception {
        when(transport.isSMB2()).thenReturn(true, false);
        assertTrue(transport.isSMB2());
        assertFalse(transport.isSMB2());
        verify(transport, times(2)).isSMB2();

        doThrow(new SmbException("query failed")).when(transport).isSMB2();
        assertThrows(SmbException.class, () -> transport.isSMB2());
        verify(transport, times(3)).isSMB2();
    }

    // Inflight requests count including edge values
    @ParameterizedTest
    @DisplayName("getInflightRequests returns various counts")
    @ValueSource(ints = { 0, 1, 42, 1000 })
    void getInflightRequests_counts(int count) {
        when(transport.getInflightRequests()).thenReturn(count);
        assertEquals(count, transport.getInflightRequests());
        verify(transport).getInflightRequests();
    }
}
