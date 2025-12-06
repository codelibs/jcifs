package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.internal.smb1.com.ServerData;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComNegotiateResponse;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComTreeConnectAndXResponse;
import org.codelibs.jcifs.smb.internal.smb2.nego.Smb2NegotiateResponse;
import org.codelibs.jcifs.smb.internal.smb2.tree.Smb2TreeConnectResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import org.codelibs.jcifs.smb.DfsReferralData;
import static org.junit.jupiter.api.Assertions.assertNull;

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
        when(context.getConfig()).thenReturn(config);
        when(session.isConnected()).thenReturn(true);
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
        // Test unwrapping to a non-assignable type should fail
        assertThrows(ClassCastException.class, () -> {
            // Create a mock class that extends SmbTree but is not assignable from SmbTreeImpl
            class CustomSmbTree extends SmbTreeImpl {
                CustomSmbTree() {
                    super(session, "SHARE", "A:");
                }
            }
            tree.unwrap(CustomSmbTree.class);
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
        when(transport.getContext()).thenReturn(context);
        when(session.getTargetHost()).thenReturn("localhost");

        // Mock negotiate response for SMB1
        SmbComNegotiateResponse nego = mock(SmbComNegotiateResponse.class);
        ServerData serverData = new ServerData();
        when(nego.getServerData()).thenReturn(serverData);
        when(transport.getNegotiateResponse()).thenReturn(nego);

        // Mock config methods needed for SMB1
        when(config.getPid()).thenReturn(1234);

        SmbComTreeConnectAndXResponse response = mock(SmbComTreeConnectAndXResponse.class);
        when(response.getService()).thenReturn("A:");
        when(response.isValidTid()).thenReturn(true);
        when(response.getTid()).thenReturn(1);
        when(session.send(any(), any())).thenReturn(response);
        when(config.isIpcSigningEnforced()).thenReturn(false);

        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");
        tree.treeConnect(null, null);

        assertTrue(tree.isConnected());
        assertEquals("A:", tree.getService());
    }

    // Test case for treeConnect method with SMB2
    @Test
    void testTreeConnectSmb2() throws CIFSException, IOException {
        when(transport.isSMB2()).thenReturn(true);
        when(transport.getContext()).thenReturn(context);
        when(session.getTargetHost()).thenReturn("localhost");

        // Mock negotiate response for SMB2
        Smb2NegotiateResponse nego = mock(Smb2NegotiateResponse.class);
        when(transport.getNegotiateResponse()).thenReturn(nego);

        Smb2TreeConnectResponse response = mock(Smb2TreeConnectResponse.class);
        when(response.getService()).thenReturn("A:");
        when(response.isValidTid()).thenReturn(true);
        when(response.getTid()).thenReturn(1);
        when(session.send(any(), any())).thenReturn(response);
        when(config.isIpcSigningEnforced()).thenReturn(false);

        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");
        tree.treeConnect(null, null);

        assertTrue(tree.isConnected());
        assertEquals("A:", tree.getService());
    }

    // Test case for treeDisconnect method
    @Test
    void testTreeDisconnect() throws CIFSException, IOException {
        when(transport.isSMB2()).thenReturn(true);
        when(transport.getContext()).thenReturn(context);
        when(session.getTargetHost()).thenReturn("localhost");

        // Mock negotiate response for SMB2
        Smb2NegotiateResponse nego = mock(Smb2NegotiateResponse.class);
        when(transport.getNegotiateResponse()).thenReturn(nego);

        Smb2TreeConnectResponse response = mock(Smb2TreeConnectResponse.class);
        when(response.getService()).thenReturn("A:");
        when(response.isValidTid()).thenReturn(true);
        when(response.getTid()).thenReturn(1);
        when(session.send(any(), any())).thenReturn(response);
        when(config.isIpcSigningEnforced()).thenReturn(false);

        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");
        tree.treeConnect(null, null);
        assertTrue(tree.isConnected());

        tree.treeDisconnect(false, false);
        assertFalse(tree.isConnected());
    }

    // ========================================
    // DFS Referral Multiple Support Tests
    // ========================================

    /**
     * Test setting and getting a single tree referral (backward compatibility)
     */
    @Test
    void testSetAndGetTreeReferral_singleReferral() {
        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");

        // Create mock referral
        DfsReferralData referral = mock(DfsReferralData.class);
        when(referral.getLink()).thenReturn("/path/to/resource");
        when(referral.getServer()).thenReturn("server1");

        // Set referral with path
        tree.setTreeReferral(referral, "/path/to/resource");

        // Get referral by exact path
        DfsReferralData result = tree.getTreeReferral("/path/to/resource");
        assertNotNull(result);
        assertEquals(referral, result);
    }

    /**
     * Test setting tree referral with both link and path
     */
    @Test
    void testSetTreeReferral_withLinkAndPath() {
        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");

        // Create mock referral
        DfsReferralData referral = mock(DfsReferralData.class);
        when(referral.getLink()).thenReturn("/link/path");

        // Set referral with different path
        tree.setTreeReferral(referral, "/actual/path");

        // Should be retrievable by both link and path
        DfsReferralData byLink = tree.getTreeReferral("/link/path");
        DfsReferralData byPath = tree.getTreeReferral("/actual/path");

        assertNotNull(byLink);
        assertNotNull(byPath);
        assertEquals(referral, byLink);
        assertEquals(referral, byPath);
    }

    /**
     * Test setting tree referral with null path
     */
    @Test
    void testSetTreeReferral_nullPath() {
        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");

        // Create mock referral with link only
        DfsReferralData referral = mock(DfsReferralData.class);
        when(referral.getLink()).thenReturn("/link/only");

        // Set referral with null path
        tree.setTreeReferral(referral, null);

        // Should be retrievable by link only
        DfsReferralData byLink = tree.getTreeReferral("/link/only");
        assertNotNull(byLink);
        assertEquals(referral, byLink);
    }

    /**
     * Test setting tree referral with null link
     */
    @Test
    void testSetTreeReferral_nullLink() {
        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");

        // Create mock referral with null link
        DfsReferralData referral = mock(DfsReferralData.class);
        when(referral.getLink()).thenReturn(null);

        // Set referral with path only
        tree.setTreeReferral(referral, "/path/only");

        // Should be retrievable by path only
        DfsReferralData byPath = tree.getTreeReferral("/path/only");
        assertNotNull(byPath);
        assertEquals(referral, byPath);
    }

    /**
     * Test setting and getting multiple tree referrals
     */
    @Test
    void testSetAndGetTreeReferral_multipleReferrals() {
        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");

        // Create multiple mock referrals
        DfsReferralData referral1 = mock(DfsReferralData.class);
        when(referral1.getLink()).thenReturn("/path1");

        DfsReferralData referral2 = mock(DfsReferralData.class);
        when(referral2.getLink()).thenReturn("/path2");

        DfsReferralData referral3 = mock(DfsReferralData.class);
        when(referral3.getLink()).thenReturn("/path3");

        // Set multiple referrals
        tree.setTreeReferral(referral1, "/path1");
        tree.setTreeReferral(referral2, "/path2");
        tree.setTreeReferral(referral3, "/path3");

        // All should be retrievable
        assertEquals(referral1, tree.getTreeReferral("/path1"));
        assertEquals(referral2, tree.getTreeReferral("/path2"));
        assertEquals(referral3, tree.getTreeReferral("/path3"));
    }

    /**
     * Test prefix matching behavior
     */
    @Test
    void testGetTreeReferral_prefixMatching() {
        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");

        // Create mock referral
        DfsReferralData referral = mock(DfsReferralData.class);
        when(referral.getLink()).thenReturn("/root/dir");

        tree.setTreeReferral(referral, "/root/dir");

        // Exact match should work
        assertNotNull(tree.getTreeReferral("/root/dir"));

        // Prefix match should work (path starts with registered path)
        assertNotNull(tree.getTreeReferral("/root/dir/subdir"));
        assertNotNull(tree.getTreeReferral("/root/dir/subdir/file.txt"));

        // Non-matching prefix should return null
        assertNull(tree.getTreeReferral("/other/path"));
        assertNull(tree.getTreeReferral("/root")); // Partial match of path component
    }

    /**
     * Test behavior when multiple prefixes match
     */
    @Test
    void testGetTreeReferral_multiplePrefixMatches() {
        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");

        // Create mock referrals with overlapping paths
        DfsReferralData referral1 = mock(DfsReferralData.class);
        when(referral1.getLink()).thenReturn("/root");
        when(referral1.getServer()).thenReturn("server1");

        DfsReferralData referral2 = mock(DfsReferralData.class);
        when(referral2.getLink()).thenReturn("/root/subdir");
        when(referral2.getServer()).thenReturn("server2");

        tree.setTreeReferral(referral1, "/root");
        tree.setTreeReferral(referral2, "/root/subdir");

        // When multiple prefixes match, should return one of them
        // (The implementation returns the first match found)
        DfsReferralData result = tree.getTreeReferral("/root/subdir/file.txt");
        assertNotNull(result);
        assertTrue(result == referral1 || result == referral2);
    }

    /**
     * Test overwriting same path
     */
    @Test
    void testSetTreeReferral_overwriteSamePath() {
        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");

        // Create two different referrals
        DfsReferralData referral1 = mock(DfsReferralData.class);
        when(referral1.getLink()).thenReturn("/path");
        when(referral1.getServer()).thenReturn("server1");

        DfsReferralData referral2 = mock(DfsReferralData.class);
        when(referral2.getLink()).thenReturn("/path");
        when(referral2.getServer()).thenReturn("server2");

        // Set first referral
        tree.setTreeReferral(referral1, "/path");
        assertEquals(referral1, tree.getTreeReferral("/path"));

        // Overwrite with second referral
        tree.setTreeReferral(referral2, "/path");
        assertEquals(referral2, tree.getTreeReferral("/path"));
    }

    /**
     * Test getting tree referral with null path
     */
    @Test
    void testGetTreeReferral_nullPath() {
        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");

        // Create and set a referral
        DfsReferralData referral = mock(DfsReferralData.class);
        when(referral.getLink()).thenReturn("/path");
        tree.setTreeReferral(referral, "/path");

        // Getting with null path should return null
        assertNull(tree.getTreeReferral(null));
    }

    /**
     * Test getting tree referral with empty path
     */
    @Test
    void testGetTreeReferral_emptyPath() {
        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");

        // Create and set a referral
        DfsReferralData referral = mock(DfsReferralData.class);
        when(referral.getLink()).thenReturn("/path");
        tree.setTreeReferral(referral, "/path");

        // Getting with empty path should return null (no prefix match)
        assertNull(tree.getTreeReferral(""));
    }

    /**
     * Test getting tree referral when no referrals are set
     */
    @Test
    void testGetTreeReferral_noReferralsSet() {
        SmbTreeImpl tree = new SmbTreeImpl(session, "SHARE", "A:");

        // Getting any path should return null when no referrals are set
        assertNull(tree.getTreeReferral("/any/path"));
    }

    // ========================================
    // Share Case Preservation Tests
    // ========================================

    /**
     * Test that share name is converted to uppercase by default (preserveShareCase = false)
     */
    @Test
    void testShareCaseConvertedToUppercaseByDefault() {
        // Given: preserveShareCase is false (default)
        when(config.isPreserveShareCase()).thenReturn(false);

        // When: creating a tree with mixed case share name
        SmbTreeImpl tree = new SmbTreeImpl(session, "MixedCaseShare", "A:");

        // Then: share name should be converted to uppercase
        assertEquals("MIXEDCASESHARE", tree.getShare());
    }

    /**
     * Test that share name case is preserved when preserveShareCase is true
     */
    @Test
    void testShareCasePreservedWhenConfigured() {
        // Given: preserveShareCase is true
        when(config.isPreserveShareCase()).thenReturn(true);

        // When: creating a tree with mixed case share name
        SmbTreeImpl tree = new SmbTreeImpl(session, "MixedCaseShare", "A:");

        // Then: share name should preserve original case
        assertEquals("MixedCaseShare", tree.getShare());
    }

    /**
     * Test that lowercase share name is preserved when preserveShareCase is true
     */
    @Test
    void testLowercaseShareCasePreserved() {
        // Given: preserveShareCase is true
        when(config.isPreserveShareCase()).thenReturn(true);

        // When: creating a tree with lowercase share name
        SmbTreeImpl tree = new SmbTreeImpl(session, "lowercaseshare", "A:");

        // Then: share name should remain lowercase
        assertEquals("lowercaseshare", tree.getShare());
    }

    /**
     * Test that uppercase share name remains uppercase when preserveShareCase is true
     */
    @Test
    void testUppercaseShareCasePreserved() {
        // Given: preserveShareCase is true
        when(config.isPreserveShareCase()).thenReturn(true);

        // When: creating a tree with uppercase share name
        SmbTreeImpl tree = new SmbTreeImpl(session, "UPPERCASESHARE", "A:");

        // Then: share name should remain uppercase
        assertEquals("UPPERCASESHARE", tree.getShare());
    }

    /**
     * Test matches method works correctly with case-preserved share names
     */
    @Test
    void testMatchesWithCasePreservedShare() {
        // Given: preserveShareCase is true
        when(config.isPreserveShareCase()).thenReturn(true);

        // When: creating a tree with mixed case share name
        SmbTreeImpl tree = new SmbTreeImpl(session, "MixedCase", "A:");

        // Then: matches should work case-insensitively
        assertTrue(tree.matches("MixedCase", "A:"));
        assertTrue(tree.matches("mixedcase", "A:"));
        assertTrue(tree.matches("MIXEDCASE", "A:"));
        assertFalse(tree.matches("OtherShare", "A:"));
    }

    /**
     * Test DFS share name like the reported issue (e.g., "SHAREname")
     */
    @Test
    void testDfsStyleShareNamePreserved() {
        // Given: preserveShareCase is true (for DFS namespaces with case-sensitive links)
        when(config.isPreserveShareCase()).thenReturn(true);

        // When: creating a tree with DFS-style mixed case share name
        SmbTreeImpl tree = new SmbTreeImpl(session, "SHAREname", "A:");

        // Then: share name should preserve exact case for DFS compatibility
        assertEquals("SHAREname", tree.getShare());
    }
}
