package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;

import jcifs.CIFSContext;
import jcifs.Credentials;
import jcifs.DfsReferralData;
import jcifs.SmbTransport;
import jcifs.SmbTransportPool;
import jcifs.config.BaseConfiguration;
import jcifs.context.BaseContext;
import jcifs.internal.dfs.DfsReferralDataInternal;

class DfsImplTest {

    private DfsImpl dfsImpl;
    private CIFSContext mockContext;
    private BaseConfiguration mockConfig;
    private Credentials mockCredentials;
    private SmbTransportPool mockTransportPool;
    private SmbTransport mockTransport;

    @BeforeEach
    void setUp() throws IOException {
        // Mock the CIFSContext and its dependencies
        mockConfig = mock(BaseConfiguration.class);
        mockCredentials = mock(Credentials.class);
        mockTransportPool = mock(SmbTransportPool.class);
        mockTransport = mock(SmbTransport.class, Answers.RETURNS_DEEP_STUBS);

        // Use a real BaseContext with mocked components
        mockContext = new BaseContext(mockConfig);
        when(mockConfig.getDfsTtl()).thenReturn(300L);
        when(mockContext.getCredentials()).thenReturn(mockCredentials);
        when(mockContext.getTransportPool()).thenReturn(mockTransportPool);

        // Mock transport retrieval
        when(mockTransportPool.getSmbTransport(any(CIFSContext.class), anyString(), anyInt(), anyBoolean(), anyBoolean())).thenReturn(mockTransport);
        when(mockTransport.unwrap(SmbTransportInternal.class)).thenReturn(mock(SmbTransportInternal.class));


        // Instantiate the class under test
        dfsImpl = new DfsImpl(mockContext);
    }

    // Test for the constructor
    @Test
    void testDfsImplConstructor() {
        // The constructor is called in setUp(), so if no exception is thrown, this test passes.
        assertNotNull(dfsImpl);
    }

    // Tests for isTrustedDomain
    @Test
    void testIsTrustedDomain_DfsDisabled() throws SmbAuthException {
        // Scenario: DFS is disabled in the configuration.
        when(mockConfig.isDfsDisabled()).thenReturn(true);
        assertFalse(dfsImpl.isTrustedDomain(mockContext, "anydomain.com"));
    }

    @Test
    void testIsTrustedDomain_NoUserDomain() throws SmbAuthException {
        // Scenario: The user credentials do not specify a domain.
        when(mockCredentials.getUserDomain()).thenReturn(null);
        assertFalse(dfsImpl.isTrustedDomain(mockContext, "anydomain.com"));
    }

    @Test
    void testIsTrustedDomain_UntrustedDomain() throws SmbAuthException {
        // Scenario: The domain is not in the list of trusted domains.
        when(mockCredentials.getUserDomain()).thenReturn("authdomain.com");
        // This will cause getTrustedDomains to return an empty map initially
        assertFalse(dfsImpl.isTrustedDomain(mockContext, "untrusted.com"));
    }

    // Tests for getDc
    @Test
    void testGetDc_DfsDisabled() throws SmbAuthException {
        // Scenario: DFS is disabled.
        when(mockConfig.isDfsDisabled()).thenReturn(true);
        assertNull(dfsImpl.getDc(mockContext, "anydomain.com"));
    }

    @Test
    void testGetDc_NoReferral() throws SmbAuthException {
        // Scenario: No DC referral is found for the domain.
        when(mockCredentials.getUserDomain()).thenReturn("authdomain.com");
        assertNull(dfsImpl.getDc(mockContext, "anydomain.com"));
    }

    // Tests for resolve
    @Test
    void testResolve_DfsDisabled() throws SmbAuthException {
        // Scenario: DFS is disabled.
        when(mockConfig.isDfsDisabled()).thenReturn(true);
        assertNull(dfsImpl.resolve(mockContext, "domain", "root", "/path"));
    }

    @Test
    void testResolve_NullRoot() throws SmbAuthException {
        // Scenario: The root is null.
        assertNull(dfsImpl.resolve(mockContext, "domain", null, "/path"));
    }

    @Test
    void testResolve_NullDomain() throws SmbAuthException {
        // Scenario: The domain is null.
        assertNull(dfsImpl.resolve(mockContext, null, "root", "/path"));
    }

    // Tests for cache
    @Test
    void testCache_DfsDisabled() {
        // Scenario: DFS is disabled.
        when(mockConfig.isDfsDisabled()).thenReturn(true);
        DfsReferralData mockReferral = mock(DfsReferralData.class);
        // Should not throw any exception and simply return.
        assertDoesNotThrow(() -> dfsImpl.cache(mockContext, "\\\\server\\share\\path", mockReferral));
    }

    @Test
    void testCache_InvalidPath() {
        // Scenario: The UNC path provided is invalid.
        DfsReferralDataInternal mockReferral = mock(DfsReferralDataInternal.class);
        // Should not throw any exception.
        assertDoesNotThrow(() -> dfsImpl.cache(mockContext, "invalidpath", mockReferral));
    }

    @Test
    void testCache_ValidPath() {
        // Scenario: A valid referral is cached.
        DfsReferralDataInternal mockReferral = mock(DfsReferralDataInternal.class, Answers.RETURNS_DEEP_STUBS);
        when(mockReferral.getPathConsumed()).thenReturn(15); // e.g., "\\\\server\\share".length()
        when(mockReferral.next()).thenReturn(mockReferral); // Simple loop for the do-while
        assertDoesNotThrow(() -> dfsImpl.cache(mockContext, "\\\\server\\share\\path", mockReferral));
    }
}
