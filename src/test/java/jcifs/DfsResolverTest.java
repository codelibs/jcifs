package jcifs;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.context.BaseContext;
import jcifs.smb.DfsImpl;
import jcifs.smb.SmbAuthException;
import jcifs.smb.SmbTransportImpl;

@ExtendWith(MockitoExtension.class)
class DfsResolverTest {

    private DfsResolver dfsResolver;

    @Mock
    private CIFSContext mockContext;

    @Mock
    private Configuration mockConfig;

    @Mock
    private Credentials mockCredentials;

    @Mock
    private SmbTransportPool mockTransportPool;

    @Mock
    private SmbTransportImpl mockTransport;

    @BeforeEach
    void setUp() {
        dfsResolver = new DfsImpl(mockContext);
        when(mockContext.getConfig()).thenReturn(mockConfig);
    }

    // Test for isTrustedDomain method
    @Test
    void testIsTrustedDomain_DfsDisabled() throws CIFSException {
        when(mockConfig.isDfsDisabled()).thenReturn(true);
        assertFalse(dfsResolver.isTrustedDomain(mockContext, "anyDomain"));
    }

    @Test
    void testIsTrustedDomain_NoUserDomain() throws CIFSException {
        when(mockConfig.isDfsDisabled()).thenReturn(false);
        when(mockContext.getCredentials()).thenReturn(mockCredentials);
        when(mockCredentials.getUserDomain()).thenReturn(null);
        assertFalse(dfsResolver.isTrustedDomain(mockContext, "anyDomain"));
    }

    @Test
    void testIsTrustedDomain_EmptyUserDomain() throws CIFSException {
        when(mockConfig.isDfsDisabled()).thenReturn(false);
        when(mockContext.getCredentials()).thenReturn(mockCredentials);
        when(mockCredentials.getUserDomain()).thenReturn("");
        assertFalse(dfsResolver.isTrustedDomain(mockContext, "anyDomain"));
    }

    // Test for getDc method
    @Test
    void testGetDc_DfsDisabled() throws CIFSException {
        when(mockConfig.isDfsDisabled()).thenReturn(true);
        assertNull(dfsResolver.getDc(mockContext, "anyDomain"));
    }

    @Test
    void testGetDc_Success() throws CIFSException, IOException {
        when(mockConfig.isDfsDisabled()).thenReturn(false);
        when(mockContext.getTransportPool()).thenReturn(mockTransportPool);
        when(mockTransportPool.getSmbTransport(any(), anyString(), anyInt(), anyBoolean(), anyBoolean())).thenReturn(mockTransport);
        when(mockTransport.unwrap(any())).thenReturn(mockTransport);
        when(mockTransport.getDfsReferrals(any(), anyString(), anyString(), anyString(), anyInt())).thenReturn(null);
        assertNull(dfsResolver.getDc(mockContext, "anyDomain"));
    }

    // Test for resolve method
    @Test
    void testResolve_DfsDisabled() throws CIFSException {
        when(mockConfig.isDfsDisabled()).thenReturn(true);
        assertNull(dfsResolver.resolve(mockContext, "anyDomain", "anyRoot", "anyPath"));
    }

    @Test
    void testResolve_NullRoot() throws CIFSException {
        when(mockConfig.isDfsDisabled()).thenReturn(false);
        assertNull(dfsResolver.resolve(mockContext, "anyDomain", null, "anyPath"));
    }

    @Test
    void testResolve_IpcRoot() throws CIFSException {
        when(mockConfig.isDfsDisabled()).thenReturn(false);
        assertNull(dfsResolver.resolve(mockContext, "anyDomain", "IPC$", "anyPath"));
    }

    @Test
    void testResolve_NullDomain() throws CIFSException {
        when(mockConfig.isDfsDisabled()).thenReturn(false);
        assertNull(dfsResolver.resolve(mockContext, null, "anyRoot", "anyPath"));
    }

    // Test for cache method
    @Test
    void testCache_DfsDisabled() {
        when(mockConfig.isDfsDisabled()).thenReturn(true);
        DfsReferralData mockReferralData = mock(DfsReferralData.class);
        assertDoesNotThrow(() -> dfsResolver.cache(mockContext, "\\anyServer\anyShare\anyPath", mockReferralData));
    }

    @Test
    void testCache_InvalidPath() {
        when(mockConfig.isDfsDisabled()).thenReturn(false);
        DfsReferralData mockReferralData = mock(DfsReferralData.class);
        assertDoesNotThrow(() -> dfsResolver.cache(mockContext, "invalidPath", mockReferralData));
    }
}
