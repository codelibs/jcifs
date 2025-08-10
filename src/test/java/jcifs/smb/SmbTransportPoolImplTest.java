package jcifs.smb;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.UnknownHostException;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.Address;
import jcifs.CIFSContext;
import jcifs.Credentials;
import jcifs.NameServiceClient;
import jcifs.SmbConstants;
import jcifs.smb.SmbException;
import jcifs.SmbTransport;
import jcifs.internal.SmbNegotiationResponse;

@ExtendWith(MockitoExtension.class)
class SmbTransportPoolImplTest {

    private SmbTransportPoolImpl pool;

    @Mock private CIFSContext ctx;
    @Mock private jcifs.Configuration config;
    @Mock private NameServiceClient nameSvc;
    @Mock private Credentials creds;
    @Mock private Address address;

    @BeforeEach
    void setUp() {
        pool = new SmbTransportPoolImpl();

        when(ctx.getConfig()).thenReturn(config);
        when(ctx.getNameServiceClient()).thenReturn(nameSvc);
        when(ctx.getCredentials()).thenReturn(creds);
        when(ctx.getTransportPool()).thenReturn(pool);

        when(config.getLocalAddr()).thenReturn(null);
        when(config.getLocalPort()).thenReturn(0);
        when(config.getSessionLimit()).thenReturn(10);
        when(config.isSigningEnforced()).thenReturn(false);
        when(config.isIpcSigningEnforced()).thenReturn(true);
        when(config.getLogonShare()).thenReturn("IPC$");

        when(creds.isAnonymous()).thenReturn(false);

        when(address.getHostName()).thenReturn("host.example");
        when(address.getHostAddress()).thenReturn("10.0.0.1");
    }

    // Helper to set a pre-negotiated response to avoid network calls via ensureConnected()
    private static void setNegotiated(SmbTransportImpl trans, SmbNegotiationResponse nego) {
        try {
            Field f = SmbTransportImpl.class.getDeclaredField("negotiated");
            f.setAccessible(true);
            f.set(trans, nego);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("contains(): pooled vs. non-pooled behavior")
    void testContainsAndNonPooledBehavior() {
        // Arrange two connections: one pooled, one non-pooled
        SmbTransportImpl pooled = pool.getSmbTransport(ctx, address, 445, false);
        SmbTransportImpl nonPooled = pool.getSmbTransport(ctx, address, 445, true);

        // Assert pooled is tracked, non-pooled is not
        assertTrue(pool.contains(pooled));
        assertFalse(pool.contains(nonPooled));
    }

    @Test
    @DisplayName("Reuses pooled connection when eligible")
    void testReusePooledConnectionWhenEligible() throws Exception {
        SmbTransportImpl first = pool.getSmbTransport(ctx, address, 445, false);
        SmbNegotiationResponse nego = mock(SmbNegotiationResponse.class);
        when(nego.isSigningRequired()).thenReturn(false);
        when(nego.isSigningNegotiated()).thenReturn(false);
        when(nego.canReuse(eq(ctx), eq(false))).thenReturn(true);
        setNegotiated(first, nego);

        SmbTransportImpl second = pool.getSmbTransport(ctx, address, 445, false);
        assertSame(first, second);
    }

    @Test
    @DisplayName("Does not reuse when forceSigning required on new call")
    void testNoReuseWhenForceSigningRequested() throws Exception {
        SmbTransportImpl initial = pool.getSmbTransport(ctx, address, 445, false, false);
        SmbNegotiationResponse nego = mock(SmbNegotiationResponse.class);
        when(nego.isSigningRequired()).thenReturn(false);
        when(nego.isSigningNegotiated()).thenReturn(false);
        when(nego.canReuse(eq(ctx), eq(true))).thenReturn(true);
        setNegotiated(initial, nego);

        SmbTransportImpl created = pool.getSmbTransport(ctx, address, 445, false, true);
        assertNotSame(initial, created);
    }

    @Test
    @DisplayName("Does not reuse when existing has signing enforced but not required")
    void testNoReuseWhenExistingHasSigningEnforcedButNotRequired() throws Exception {
        SmbTransportImpl enforced = pool.getSmbTransport(ctx, address, 445, false, true);
        SmbNegotiationResponse nego = mock(SmbNegotiationResponse.class);
        when(nego.isSigningRequired()).thenReturn(false);
        when(nego.isSigningNegotiated()).thenReturn(true);
        when(nego.canReuse(eq(ctx), eq(false))).thenReturn(true);
        setNegotiated(enforced, nego);

        when(config.isSigningEnforced()).thenReturn(false);
        SmbTransportImpl created = pool.getSmbTransport(ctx, address, 445, false, false);
        assertNotSame(enforced, created);
    }

    @Test
    @DisplayName("removeTransport(): connection removed on next cleanup")
    void testRemoveTransportAndCleanup() {
        SmbTransportImpl t = pool.getSmbTransport(ctx, address, 445, false);
        assertTrue(pool.contains(t));
        pool.removeTransport(t);
        assertFalse(pool.contains(t));
    }

    @Test
    @DisplayName("close(): closes all and returns in-use flag")
    void testCloseClosesAll() throws Exception {
        // Create real entries, then replace with spies via reflection
        SmbTransportImpl pooledReal = pool.getSmbTransport(ctx, address, 445, false);
        SmbTransportImpl nonPooledReal = pool.getSmbTransport(ctx, address, 445, true);
        SmbTransportImpl pooledSpy = spy(pooledReal);
        SmbTransportImpl nonPooledSpy = spy(nonPooledReal);

        Field connsF = SmbTransportPoolImpl.class.getDeclaredField("connections");
        connsF.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<SmbTransportImpl> conns = (List<SmbTransportImpl>) connsF.get(pool);
        int idx = conns.indexOf(pooledReal);
        conns.set(idx, pooledSpy);

        Field nonConnsF = SmbTransportPoolImpl.class.getDeclaredField("nonPooledConnections");
        nonConnsF.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<SmbTransportImpl> nonConns = (List<SmbTransportImpl>) nonConnsF.get(pool);
        int idx2 = nonConns.indexOf(nonPooledReal);
        nonConns.set(idx2, nonPooledSpy);

        when(pooledSpy.disconnect(false, false)).thenReturn(true);
        when(nonPooledSpy.disconnect(false, false)).thenReturn(false);

        boolean inUse = pool.close();

        assertTrue(inUse);
        verify(pooledSpy, times(1)).disconnect(false, false);
        verify(nonPooledSpy, times(1)).disconnect(false, false);
    }

    @Test
    @DisplayName("getChallenge(): returns server key and wraps IOExceptions")
    void testGetChallenge() throws Exception {
        SmbTransportPoolImpl poolSpy = spy(pool);
        when(ctx.getTransportPool()).thenReturn(poolSpy);

        SmbTransportInternal internal = mock(SmbTransportInternal.class);
        when(internal.ensureConnected()).thenReturn(true);
        when(internal.getServerEncryptionKey()).thenReturn(new byte[] {1,2,3});
        SmbTransportImpl wrapper = mock(SmbTransportImpl.class);
        when(wrapper.unwrap(SmbTransportInternal.class)).thenReturn(internal);

        when(poolSpy.getSmbTransport(eq(ctx), any(Address.class), anyInt(), eq(false), anyBoolean())).thenReturn(wrapper);

        byte[] key = poolSpy.getChallenge(ctx, address);
        assertArrayEquals(new byte[] {1,2,3}, key);
        verify(internal, times(1)).ensureConnected();

        reset(internal);
        when(wrapper.unwrap(SmbTransportInternal.class)).thenReturn(internal);
        when(internal.ensureConnected()).thenThrow(new IOException("boom"));
        SmbException ex = assertThrows(SmbException.class, () -> poolSpy.getChallenge(ctx, address));
        assertTrue(ex.getMessage().contains("Connection failed"));
    }

    @Test
    @DisplayName("logon(): connects to logon share and invokes connectLogon")
    void testLogon() throws Exception {
        SmbTransportPoolImpl poolSpy = spy(pool);
        when(ctx.getTransportPool()).thenReturn(poolSpy);
        when(address.getHostName()).thenReturn("server.local");

        SmbTreeInternal tree = mock(SmbTreeInternal.class);
        SmbSessionInternal session = mock(SmbSessionInternal.class);
        SmbTransportInternal internal = mock(SmbTransportInternal.class);

        when(internal.getSmbSession(eq(ctx), eq("server.local"), isNull())).thenReturn(session);
        when(session.getSmbTree(eq("IPC$"), isNull())).thenReturn(tree);

        SmbTransportImpl wrapper = mock(SmbTransportImpl.class);
        when(wrapper.unwrap(SmbTransportInternal.class)).thenReturn(internal);
        when(session.unwrap(SmbSessionInternal.class)).thenReturn(session);
        when(tree.unwrap(SmbTreeInternal.class)).thenReturn(tree);

        when(poolSpy.getSmbTransport(eq(ctx), eq(address), anyInt(), eq(false), anyBoolean())).thenReturn(wrapper);

        poolSpy.logon(ctx, address);
        verify(tree, times(1)).connectLogon(eq(ctx));
    }

    @Test
    @DisplayName("getSmbTransport(name): sorts by fail counts, tries until success")
    void testGetSmbTransportByNameOrderingAndFailover() throws Exception {
        SmbTransportPoolImpl poolSpy = spy(pool);
        when(ctx.getTransportPool()).thenReturn(poolSpy);

        Address a1 = mock(Address.class);
        when(a1.getHostAddress()).thenReturn("10.0.0.1");
        Address a2 = mock(Address.class);
        when(a2.getHostAddress()).thenReturn("10.0.0.2");

        when(nameSvc.getAllByName(eq("srv"), eq(true))).thenReturn(new Address[] {a1, a2});

        poolSpy.failCounts.put("10.0.0.1", 5);
        poolSpy.failCounts.put("10.0.0.2", 1);

        SmbTransportImpl t1 = mock(SmbTransportImpl.class);
        SmbTransportImpl t2 = mock(SmbTransportImpl.class);
        when(t1.unwrap(SmbTransportImpl.class)).thenCallRealMethod();
        when(t2.unwrap(SmbTransportImpl.class)).thenCallRealMethod();
        when(t1.ensureConnected()).thenThrow(new IOException("addr1-fail"));
        when(t2.ensureConnected()).thenReturn(true);
        when(t2.acquire()).thenReturn(t2);

        when(poolSpy.getSmbTransport(eq(ctx), eq(a2), anyInt(), anyBoolean(), anyBoolean())).thenReturn(t2);
        when(poolSpy.getSmbTransport(eq(ctx), eq(a1), anyInt(), anyBoolean(), anyBoolean())).thenReturn(t1);

        SmbTransportImpl result = poolSpy.getSmbTransport(ctx, "srv", 445, false, false);

        assertSame(t2, result);
        verify(poolSpy, atLeastOnce()).getSmbTransport(eq(ctx), eq(a2), anyInt(), anyBoolean(), anyBoolean());
        assertEquals(Integer.valueOf(6), poolSpy.failCounts.get("10.0.0.1"));
    }

    @Test
    @DisplayName("getSmbTransport(name): throws UnknownHostException for no addresses")
    void testGetSmbTransportByNameNoAddresses() throws Exception {
        when(nameSvc.getAllByName(eq("unknown"), eq(true))).thenReturn(new Address[0]);
        assertThrows(UnknownHostException.class, () -> pool.getSmbTransport(ctx, "unknown", 0, false, false));
    }

    @Test
    @DisplayName("getSmbTransport(name): throws last IOException on complete failure")
    void testGetSmbTransportByNameAllFail() throws Exception {
        SmbTransportPoolImpl poolSpy = spy(pool);
        when(ctx.getTransportPool()).thenReturn(poolSpy);

        Address a1 = mock(Address.class);
        when(a1.getHostAddress()).thenReturn("10.0.0.3");
        Address a2 = mock(Address.class);
        when(a2.getHostAddress()).thenReturn("10.0.0.4");
        when(nameSvc.getAllByName(eq("srv2"), eq(true))).thenReturn(new Address[] {a1, a2});

        SmbTransportImpl t1 = mock(SmbTransportImpl.class);
        SmbTransportImpl t2 = mock(SmbTransportImpl.class);
        when(t1.unwrap(SmbTransportImpl.class)).thenCallRealMethod();
        when(t2.unwrap(SmbTransportImpl.class)).thenCallRealMethod();
        when(t1.ensureConnected()).thenThrow(new IOException("first"));
        IOException last = new IOException("second");
        when(t2.ensureConnected()).thenThrow(last);

        when(poolSpy.getSmbTransport(eq(ctx), eq(a1), anyInt(), anyBoolean(), anyBoolean())).thenReturn(t1);
        when(poolSpy.getSmbTransport(eq(ctx), eq(a2), anyInt(), anyBoolean(), anyBoolean())).thenReturn(t2);

        IOException thrown = assertThrows(IOException.class, () -> poolSpy.getSmbTransport(ctx, "srv2", 0, false, false));
        assertSame(last, thrown);
        assertEquals(Integer.valueOf(1), poolSpy.failCounts.get("10.0.0.3"));
        assertEquals(Integer.valueOf(1), poolSpy.failCounts.get("10.0.0.4"));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1})
    @DisplayName("Port <= 0 defaults to 445 and allows reuse")
    void testPortDefaultsAndReuse(int invalidPort) throws Exception {
        SmbTransportImpl first = pool.getSmbTransport(ctx, address, invalidPort, false);
        SmbNegotiationResponse nego = mock(SmbNegotiationResponse.class);
        when(nego.isSigningRequired()).thenReturn(false);
        when(nego.isSigningNegotiated()).thenReturn(false);
        when(nego.canReuse(eq(ctx), eq(false))).thenReturn(true);
        setNegotiated(first, nego);

        SmbTransportImpl second = pool.getSmbTransport(ctx, address, SmbConstants.DEFAULT_PORT, false);
        assertSame(first, second);
    }
}

