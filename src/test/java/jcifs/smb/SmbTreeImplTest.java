package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.SmbConstants;
import jcifs.internal.smb1.com.SmbComTreeConnectAndXResponse;
import jcifs.internal.smb2.tree.Smb2TreeConnectResponse;

class SmbTreeImplTest {

    @Mock
    private SmbSessionImpl session;

    @Mock
    private Configuration config;

    @Mock
    private CIFSContext context;

    @Mock
    private SmbTransportImpl transport;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        when(session.getConfig()).thenReturn(config);
        when(session.getContext()).thenReturn(context);
        when(session.getTransport()).thenReturn(transport);
        when(session.acquire()).thenReturn(session);
        when(config.isTraceResourceUsage()).thenReturn(false);
    }

    // Test case for the constructor of SmbTreeImpl
    @Test
    void testSmbTreeImplConstructor() {
        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");
        assertNotNull(tree);
        assertEquals("SHARE", tree.getShare());
        assertEquals("A:", tree.getService());
    }

    // Test case for the matches method
    @Test
    void testMatches() {
        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");
        assertTrue(tree.matches("share", "A:"));
        assertFalse(tree.matches("othershare", "A:"));
    }

    // Test case for the equals method
    @Test
    void testEquals() {
        SmbTreeImpl tree1 = new SmbTreeImpl(session, "SHARE", "A:");
        SmbTreeImpl tree2 = new SmbTreeImpl(session, "SHARE", "A:");
        SmbTreeImpl tree3 = new SmbTreeImpl(session, "OTHER", "A:");
        assertEquals(tree1, tree2);
        assertFalse(tree1.equals(tree3));
    }

    // Test case for the unwrap method
    @Test
    void testUnwrap() {
        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");
        SmbTreeImpl unwrapped = tree.unwrap(SmbTreeImpl.class);
        assertEquals(tree, unwrapped);
        // Test unwrapping to a non-SmbTree type should fail
        assertThrows(ClassCastException.class, () -> {
            // Try to unwrap to Object which is not a subtype of SmbTree
            tree.unwrap((Class) Object.class);
        });
    }

    // Test case for acquire and release methods
    @Test
    void testAcquireAndRelease() {
        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");
        tree.acquire();
        tree.release();
    }

    // Test case for isConnected method
    @Test
    void testIsConnected() throws CIFSException, IOException {
        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");
        assertFalse(tree.isConnected());
    }

    // Test case for getTreeType method
    @Test
    void testGetTreeType() {
        SmbTreeImpl tree1 = new SmbTreeImpl(session, "SHARE", "A:");
        assertEquals(SmbConstants.TYPE_SHARE, tree1.getTreeType());

        SmbTreeImpl tree2 = new SmbTreeImpl(session, "LPT1", "LPT1:");
        assertEquals(SmbConstants.TYPE_PRINTER, tree2.getTreeType());

        SmbTreeImpl tree3 = new SmbTreeImpl(session, "COMM", "COMM");
        assertEquals(SmbConstants.TYPE_COMM, tree3.getTreeType());
    }

    // Test case for DFS related methods
    @Test
    void testDfs() throws SmbException {
        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");
        assertFalse(tree.isDfs());
        assertFalse(tree.isInDomainDfs());
        tree.markDomainDfs();
        assertTrue(tree.isInDomainDfs());
    }

    // Test case for treeConnect method with SMB1
    @Test
    void testTreeConnectSmb1() throws CIFSException, IOException {
        when(transport.isSMB2()).thenReturn(false);
        when(session.getTargetHost()).thenReturn("localhost");
        SmbComTreeConnectAndXResponse response = mock(SmbComTreeConnectAndXResponse.class);
        when(response.getService()).thenReturn("A:");
        when(response.isValidTid()).thenReturn(true);
        when(session.send(any(), any())).thenReturn(response);

        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");
        tree.treeConnect(null, null);

        assertTrue(tree.isConnected());
        assertEquals("A:", tree.getService());
    }

    // Test case for treeConnect method with SMB2
    @Test
    void testTreeConnectSmb2() throws CIFSException, IOException {
        when(transport.isSMB2()).thenReturn(true);
        when(session.getTargetHost()).thenReturn("localhost");
        Smb2TreeConnectResponse response = mock(Smb2TreeConnectResponse.class);
        when(response.getService()).thenReturn("A:");
        when(response.isValidTid()).thenReturn(true);
        when(session.send(any(), any())).thenReturn(response);

        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");
        tree.treeConnect(null, null);

        assertTrue(tree.isConnected());
        assertEquals("A:", tree.getService());
    }

    // Test case for treeDisconnect method
    @Test
    void testTreeDisconnect() throws CIFSException, IOException {
        when(transport.isSMB2()).thenReturn(true);
        when(session.getTargetHost()).thenReturn("localhost");
        Smb2TreeConnectResponse response = mock(Smb2TreeConnectResponse.class);
        when(response.getService()).thenReturn("A:");
        when(response.isValidTid()).thenReturn(true);
        when(session.send(any(), any())).thenReturn(response);

        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");
        tree.treeConnect(null, null);
        assertTrue(tree.isConnected());

        tree.treeDisconnect(false, false);
        assertFalse(tree.isConnected());
    }
}
