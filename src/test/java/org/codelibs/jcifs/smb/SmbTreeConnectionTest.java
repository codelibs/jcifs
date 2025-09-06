package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.net.URL;
import java.util.EnumSet;

import org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlockResponse;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComClose;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SmbTreeConnectionTest {

    @Mock
    CIFSContext ctx;

    @Mock
    Configuration config;

    @Mock
    Credentials credentials;

    @Mock
    DfsResolver dfsResolver;

    private SmbTreeConnection newConn() {
        return new SmbTreeConnection(ctx) {
        };
    }

    @BeforeEach
    void setup() {
        when(ctx.getConfig()).thenReturn(config);
        // keep retries small for faster and deterministic tests
        when(config.getMaxRequestRetries()).thenReturn(2);
        when(config.isTraceResourceUsage()).thenReturn(false);
        // Mock credentials to avoid NullPointerException
        when(ctx.getCredentials()).thenReturn(credentials);
        when(credentials.getUserDomain()).thenReturn("DOMAIN");
        // Mock DFS resolver
        when(ctx.getDfs()).thenReturn(dfsResolver);
    }

    // Helper to set private field 'tree'
    private static void setTree(SmbTreeConnection c, SmbTreeImpl tree) {
        try {
            Field f = SmbTreeConnection.class.getDeclaredField("tree");
            f.setAccessible(true);
            f.set(c, tree);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    // Helper to set private flag 'treeAcquired'
    private static void setTreeAcquired(SmbTreeConnection c, boolean val) {
        try {
            Field f = SmbTreeConnection.class.getDeclaredField("treeAcquired");
            f.setAccessible(true);
            f.set(c, val);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    // Helper to build a minimal smb URL
    private static URL smbUrl(String spec) throws Exception {
        return new URL(null, spec, new Handler());
    }

    @Test
    @DisplayName("getConfig returns context config")
    void getConfig_returnsConfig() {
        SmbTreeConnection c = newConn();
        assertSame(config, c.getConfig());
    }

    @Test
    @DisplayName("acquire calls tree.acquire on first usage, release calls tree.release at zero")
    void acquire_release_lifecycle() {
        SmbTreeConnection c = newConn();
        SmbTreeImpl tree = mock(SmbTreeImpl.class);
        when(tree.acquire(false)).thenReturn(tree);
        when(tree.acquire()).thenReturn(tree);

        setTree(c, tree);

        // Act: first acquire triggers tree.acquire()
        c.acquire();
        verify(tree, times(1)).acquire();

        // Act: second acquire does not call tree.acquire again
        c.acquire();
        verify(tree, times(1)).acquire();

        // Act: first release does not release yet (usage -> 1)
        c.release();
        verify(tree, never()).release();

        // Act: second release (usage -> 0) releases the tree
        c.release();
        verify(tree, times(1)).release();
    }

    @Test
    @DisplayName("release below zero throws RuntimeCIFSException")
    void release_belowZero_throws() {
        SmbTreeConnection c = newConn();
        RuntimeCIFSException ex = assertThrows(RuntimeCIFSException.class, c::release);
        assertTrue(ex.getMessage().toLowerCase().contains("usage count"));
    }

    @Test
    @DisplayName("isConnected reflects underlying tree state")
    void isConnected_usesTree() {
        SmbTreeConnection c = newConn();
        // No tree -> false
        assertFalse(c.isConnected());

        SmbTreeImpl tree = mock(SmbTreeImpl.class);
        when(tree.isConnected()).thenReturn(true);
        setTree(c, tree);
        assertTrue(c.isConnected());
    }

    @Test
    @DisplayName("getTreeId returns -1 when no tree")
    void getTreeId_noTree() {
        SmbTreeConnection c = newConn();
        assertEquals(-1, c.getTreeId());
    }

    @Test
    @DisplayName("getTreeType and getConnectedShare delegate to tree")
    void getters_delegateToTree() {
        SmbTreeConnection c = newConn();
        SmbTreeImpl tree = mock(SmbTreeImpl.class);
        when(tree.acquire(false)).thenReturn(tree);
        when(tree.getTreeType()).thenReturn(7);
        when(tree.getShare()).thenReturn("SHARE");
        setTree(c, tree);

        assertEquals(7, c.getTreeType());
        assertEquals("SHARE", c.getConnectedShare());
        // try-with-resources closes the acquired tree
        verify(tree, atLeastOnce()).close();
    }

    @Test
    @DisplayName("isSame returns true only for same underlying tree instance")
    void isSame_comparesUnderlyingTreeIdentity() {
        SmbTreeConnection c1 = newConn();
        SmbTreeConnection c2 = newConn();
        SmbTreeImpl shared = mock(SmbTreeImpl.class);
        when(shared.acquire(false)).thenReturn(shared);

        setTree(c1, shared);
        setTree(c2, shared);
        assertTrue(c1.isSame(c2));

        SmbTreeImpl other = mock(SmbTreeImpl.class);
        when(other.acquire(false)).thenReturn(other);
        setTree(c2, other);
        assertFalse(c1.isSame(c2));
    }

    @Test
    @DisplayName("hasCapability throws when not connected")
    void hasCapability_notConnected_throws() {
        SmbTreeConnection c = newConn();
        SmbException ex = assertThrows(SmbException.class, () -> c.hasCapability(1));
        assertTrue(ex.getMessage().contains("Not connected"));
    }

    @Test
    @DisplayName("connectWrapException wraps UnknownHostException and IOException")
    void connectWrapException_wraps_io_and_unkhost() throws Exception {
        // Subclass to control connect() behavior
        SmbTreeConnection c = new SmbTreeConnection(ctx) {
            @Override
            public SmbTreeHandleImpl connect(SmbResourceLocatorImpl loc) throws java.io.IOException {
                throw new java.net.UnknownHostException("nohost");
            }
        };

        SmbResourceLocatorImpl loc = new SmbResourceLocatorImpl(ctx, smbUrl("smb://server/share/"));
        SmbException ex1 = assertThrows(SmbException.class, () -> c.connectWrapException(loc));
        assertTrue(ex1.getMessage().contains("Failed to connect to server"));

        SmbTreeConnection c2 = new SmbTreeConnection(ctx) {
            @Override
            public SmbTreeHandleImpl connect(SmbResourceLocatorImpl loc) throws java.io.IOException {
                throw new java.io.IOException("iofail");
            }
        };
        SmbException ex2 = assertThrows(SmbException.class, () -> c2.connectWrapException(loc));
        assertTrue(ex2.getMessage().contains("Failed to connect to server"));

        SmbTreeConnection c3 = new SmbTreeConnection(ctx) {
            @Override
            public SmbTreeHandleImpl connect(SmbResourceLocatorImpl loc) throws SmbException {
                throw new SmbException("boom");
            }
        };
        SmbException ex3 = assertThrows(SmbException.class, () -> c3.connectWrapException(loc));
        assertEquals("boom", ex3.getMessage());
    }

    @Test
    @DisplayName("ensureDFSResolved returns early for SmbComClose requests")
    void ensureDFSResolved_closeRequest_noop() throws Exception {
        SmbTreeConnection c = spy(newConn());
        SmbResourceLocatorImpl loc = new SmbResourceLocatorImpl(ctx, smbUrl("smb://server/share/"));

        // Using a SmbComClose instance triggers early return without DFS/session work
        SmbComClose closeReq = mock(SmbComClose.class);
        SmbResourceLocator res = c.ensureDFSResolved(loc, closeReq);
        assertSame(loc, res);
        // No connect attempts expected
        verify(c, never()).connectWrapException(any());
    }

    @Test
    @DisplayName("send retries on transport errors and restores request/response state")
    void send_retries_on_transportError() throws Exception {
        // Create a spy to track method calls
        SmbTreeConnection c = spy(newConn());

        // Prepare a minimal locator
        SmbResourceLocatorImpl loc = new SmbResourceLocatorImpl(ctx, smbUrl("smb://srv/share/path"));

        // Setup a tree that will fail with transport error first, then succeed
        SmbTreeImpl tree = mock(SmbTreeImpl.class);
        when(tree.acquire(false)).thenReturn(tree);

        CommonServerMessageBlockRequest req = mock(CommonServerMessageBlockRequest.class);
        CommonServerMessageBlockResponse resp = mock(CommonServerMessageBlockResponse.class);

        // Configure the tree to throw transport error on first call, succeed on second
        when(tree.send(eq(req), eq(resp), anySet()))
                .thenThrow(new SmbException("transport error", new org.codelibs.jcifs.smb.util.transport.TransportException()))
                .thenReturn(resp);

        setTree(c, tree);

        // Override connectHost to avoid actual network connection on retry
        doAnswer(invocation -> {
            SmbTreeHandleImpl handle = mock(SmbTreeHandleImpl.class);
            // Re-set the same tree to continue using our mock
            setTree(c, tree);
            return handle;
        }).when(c).connectHost(any(), anyString());

        // Execute send - should retry after transport error
        try {
            c.send(loc, req, resp, EnumSet.noneOf(RequestParam.class));
        } catch (Exception e) {
            // It's ok if it fails, we just want to verify reset was called
        }

        // Request/response reset should happen on retry
        verify(req, atLeastOnce()).reset();
        verify(resp, atLeastOnce()).reset();
        // Verify disconnect was called on retry
        verify(c, atLeastOnce()).disconnect(eq(true));
    }

    @Test
    @DisplayName("send honors NO_RETRY and propagates error immediately")
    void send_noRetry_param() throws Exception {
        SmbTreeConnection c = newConn();
        SmbTreeImpl tree = mock(SmbTreeImpl.class);
        when(tree.acquire(false)).thenReturn(tree);
        setTree(c, tree);

        CommonServerMessageBlockRequest req = mock(CommonServerMessageBlockRequest.class);
        CommonServerMessageBlockResponse resp = mock(CommonServerMessageBlockResponse.class);
        when(tree.send(eq(req), eq(resp), anySet())).thenThrow(new SmbException("boom"));

        SmbException ex = assertThrows(SmbException.class,
                () -> c.send(new SmbResourceLocatorImpl(ctx, smbUrl("smb://srv/share/p")), req, resp, EnumSet.of(RequestParam.NO_RETRY)));
        assertEquals("boom", ex.getMessage());
    }

    @Test
    @DisplayName("connect returns handle if already connected")
    void connect_whenAlreadyConnected_returnsHandle() throws Exception {
        SmbTreeConnection c = spy(newConn());
        SmbTreeImpl tree = mock(SmbTreeImpl.class);
        SmbSessionImpl session = mock(SmbSessionImpl.class);
        SmbTransportImpl transport = mock(SmbTransportImpl.class);

        when(tree.isConnected()).thenReturn(true);
        when(tree.getSession()).thenReturn(session);
        when(tree.acquire(false)).thenReturn(tree);
        when(session.getTransport()).thenReturn(transport);
        when(transport.isDisconnected()).thenReturn(false);
        when(transport.getRemoteHostName()).thenReturn("host");
        setTree(c, tree);

        SmbResourceLocatorImpl loc = new SmbResourceLocatorImpl(ctx, smbUrl("smb://host/share/"));
        SmbTreeHandle h = c.connect(loc);
        assertNotNull(h);
        // No host connect attempted as we're already connected
        verify(c, never()).connectHost(any(), anyString());
    }

    @Test
    @DisplayName("getSession returns null when no tree is present")
    void getSession_nullWhenNoTree() {
        SmbTreeConnection c = newConn();
        assertNull(c.getSession());
    }
}
